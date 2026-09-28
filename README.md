# 会话与刷新令牌登录鉴权（Cookie Session + Rotating Refresh Token）

基于 FastAPI 的一套可解释、可区分拒绝原因的登录鉴权能力：

- 短时效**访问令牌** + 长时效、可轮换的**刷新令牌**；
- 令牌通过 **HttpOnly Cookie** 下发（也支持 `Authorization: Bearer`）；
- 登出/风控判定后，该会话**所有剩余凭证立即失效**；重复登出幂等，且只影响本会话；
- 刷新令牌**一次性轮换**，并带**复用检测（reuse detection）**；
- 基于角色的访问控制（RBAC），401（身份层）与 403（权限层）原因可区分；
- 错误信息与日志**不回显令牌原文/内部细节**，日志只保留令牌哈希短指纹。

## 目录结构

```
main.py                  应用入口、依赖组装、统一 AuthError 处理
app/config.py            配置项（有效期、宽限窗口、Cookie、演示用户）
app/errors.py            稳定错误码 ErrorCode 与 AuthError
app/models.py            角色、会话、访问/刷新令牌记录、请求响应模型
app/security.py          令牌生成、SHA-256 哈希、时间源、常量时间比较
app/store.py             内存存储 + 会话级锁 + 按会话/刷新族批量撤销
app/service.py           登录/登出/刷新/校验/撤销的判定逻辑与审计日志
app/deps.py              Cookie/Header 取令牌、身份+角色依赖
app/routes_auth.py       /auth/login /auth/refresh /auth/logout
app/routes_protected.py  /me 与管理员会话管理入口
tests/                   24 个端到端/并发/边界用例
```

## 令牌模型与有效期

| 令牌 | 默认有效期 | 存储 | 用途 |
| --- | --- | --- | --- |
| 访问令牌 `access_token` | **15 分钟**（`ACCESS_TOKEN_TTL_SECONDS=900`） | 服务端仅存 SHA-256 | 访问受保护接口，过期后用刷新令牌换新 |
| 刷新令牌 `refresh_token` | **14 天**（`REFRESH_TOKEN_TTL_SECONDS=1209600`） | 服务端仅存 SHA-256 | 仅用于 `/auth/refresh`，一次性轮换 |

令牌为 256-bit 熵的不透明随机串（`secrets.token_urlsafe(32)`）。
服务端从不保存明文，比对/检索全部基于 SHA-256。访问令牌也保存在服务端，
因此会话被撤销时，**尚未自然过期的访问令牌也会立即失效**（不只是刷新令牌）。

Cookie：`HttpOnly`、`SameSite=Lax`、路径 `/`；生产用 HTTPS 时设置
`COOKIE_SECURE=1` 开启 `Secure`。

## 轮换、并发与复用判定规则

每次刷新都在**会话级互斥锁**内完成“读令牌 → 判定 → 作废旧令牌 → 签发新令牌”：

1. 一张 `active` 刷新令牌成功刷新后，立即被标记为 `used` 并记录 `rotated_at`，
   同时签发一对新令牌；新令牌属于同一条**刷新族（family）**。
2. **并发宽限窗口**（`REFRESH_GRACE_WINDOW_SECONDS`，默认 30 秒）内再次出示同一张
   `used` 令牌：判定为网络重试/客户端几乎同时发起的并发刷新，**不撤销任何凭证**，
   而是把第一次轮换已签发的**同一对令牌原样返回**。
3. 超过宽限窗口仍出现 `used` 令牌：判定为**令牌泄露/复用**，立即把
   `reuse_seen` 置位并**撤销整条会话与整个刷新族**，该会话所有访问/刷新令牌立刻失效，
   返回 `401 refresh_token_reused`。

### 为什么需要宽限窗口（工程取舍）

严格的“令牌出现两次即撤销”会误伤大量正常场景：客户端超时自动重试、多标签页/多
线程几乎同时刷新、反向代理重复投递等。这些场景与攻击在**时间维度**上有明显区别：
正常并发几乎总是在第一次轮换后的极短时间内发生，而窃取令牌的攻击者通常在更晚
（或在另一台设备）重放。因此采用“**短时宽限 + 窗口内返回同一份新凭证 + 窗口外
零容忍撤销全族**”：宽限窗口内可用性优先（幂等返回，避免把用户踢下线），窗口外
安全优先。窗口时长可按客户端重试策略调整；缩短窗口更严格，加长窗口对弱网络更友好。

其余状态判定（按顺序）：会话已撤销 → 令牌已撤销 → 已过期 → 已使用（进入上面的
并发/复用分支）→ 正常轮换。

## 权限模型（RBAC）

- 角色：`admin`、`member`。
- 受保护依赖：
  - `require_roles()`：任何已登录用户（只校验身份）；
  - `require_roles(Role.ADMIN)`：需具备 `admin` 角色。
- 两道闸门结果可区分：
  - 未登录/令牌问题 → **401**，细分为 `access_token_missing` /
    `access_token_invalid` / `access_token_expired` / `access_token_revoked` /
    `session_revoked` 等；
  - 已登录但角色不足 → **403 `permission_denied`**。

演示用户（仅用于本地，生产应替换为真实用户库与密码哈希）：

| 用户名 | 密码 | 角色 |
| --- | --- | --- |
| admin | admin123 | admin, member |
| alice | alice123 | member |
| bob | bob123 | member |

## 接口一览

| 方法 | 路径 | 说明 | 拒绝示例 |
| --- | --- | --- | --- |
| POST | `/auth/login` | 登录，写入两个 Cookie | 401 `invalid_credentials` |
| POST | `/auth/refresh` | 刷新并轮换；并发回放窗口内幂等 | 401 `refresh_token_expired/revoked/reused` |
| POST | `/auth/logout` | 登出，撤销本会话全部凭证，**永远幂等成功** | — |
| GET | `/me` | 当前身份（任意已登录用户） | 401 系列 / — |
| GET | `/admin/sessions` | 查看会话（admin） | 403 `permission_denied` |
| POST | `/admin/sessions/{id}/revoke` | 风控撤销会话（admin） | 403 `permission_denied` |

错误响应统一为：

```json
{"error": {"code": "access_token_expired", "message": "访问令牌已过期"}}
```

## 配置项（环境变量）

| 变量 | 默认值 | 含义 |
| --- | --- | --- |
| `ACCESS_TOKEN_TTL_SECONDS` | `900` | 访问令牌有效期（秒） |
| `REFRESH_TOKEN_TTL_SECONDS` | `1209600` | 刷新令牌有效期（秒） |
| `REFRESH_GRACE_WINDOW_SECONDS` | `30` | 并发刷新宽限窗口（秒） |
| `COOKIE_SECURE` | `false` | 是否给 Cookie 加 `Secure`（生产 HTTPS 置 `true`） |
| `COOKIE_SAMESITE` | `lax` | Cookie SameSite 策略 |
| `COOKIE_PATH` | `/` | Cookie Path |

## 本地验证

```bash
# 安装依赖（已包含 pytest）
uv sync

# 运行全部测试（短 TTL：access 2s / refresh 60s / 宽限 1s）
uv run pytest -q

# 查看每个用例打印的“输入 + 期望/实际判定依据”
uv run pytest -s

# 查看并发刷新的审计日志（1 次 rotate + N 次 concurrent_replay）
uv run pytest tests/test_refresh_rotation.py::test_concurrent_refresh_within_grace_is_not_reuse \
  -s --log-cli-level=INFO

# 启动服务
uv run python main.py
```

手动 curl（本地默认 `COOKIE_SECURE=false`）：

```bash
# 1) 匿名访问
curl -i http://127.0.0.1:8000/me
# 401 {"error":{"code":"access_token_missing", ...}}

# 2) 登录并保存 Cookie
curl -i -c jar.txt -X POST http://127.0.0.1:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}'

# 3) 带 Cookie 访问
curl -s -b jar.txt http://127.0.0.1:8000/me

# 4) 刷新轮换（观察 Set-Cookie 中的新令牌）
curl -i -b jar.txt -c jar.txt -X POST http://127.0.0.1:8000/auth/refresh

# 5) 登出（重复调用同样返回 200，幂等）
curl -i -b jar.txt -c jar.txt -X POST http://127.0.0.1:8000/auth/logout

# 6) 登出后再访问 -> 401 session_revoked
curl -i -b jar.txt http://127.0.0.1:8000/me
```

## 测试覆盖

`tests/` 共 24 个用例，覆盖：匿名拒绝、正常登录与 `/me`、错误密码/未知用户、
RBAC 401/403 区分、访问令牌过期与刷新恢复、登出幂等且不影响他人会话、
风控管理员撤销全凭证、刷新令牌缺失/无效/过期/已撤销、
**轮换后窗口外复用 → 撤销全族**、**5 线程并发刷新仅一次轮换且无人被误踢**、
错误体与日志不泄露令牌原文。
