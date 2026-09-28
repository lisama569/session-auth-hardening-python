# 会话与刷新令牌登录鉴权（Cookie Session + Refresh Token Rotation）

基于 FastAPI 的一套登录鉴权能力：不透明令牌经 **HttpOnly Cookie** 下发，访问令牌
短时效、刷新令牌轮换并带复用检测；登出 / 风控撤销会让一条会话的全部剩余凭证立即
失效。匿名、过期、撤销、复用、无权限等状态在所有入口下返回**稳定、可区分**的错误
码，且错误响应不泄露令牌内容与内部判定细节。

## 1. 目录结构

| 文件 | 职责 |
| --- | --- |
| `main.py` | 应用装配、演示用户、统一 `AuthError` -> HTTP 响应 |
| `auth/config.py` | 令牌 TTL、宽限窗口、Cookie 选项等配置 |
| `auth/errors.py` | 稳定错误码 `AuthErrorCode` 与 HTTP 状态映射 |
| `auth/models.py` | `User` / `Session` / `RefreshTokenRecord` / `Principal` |
| `auth/security.py` | CSPRNG 令牌生成、SHA-256 哈希、口令校验（常量时间比较） |
| `auth/store.py` | 线程安全的内存存储（用户 / 会话 / 刷新令牌） |
| `auth/service.py` | 登录、幂等登出、轮换 + 复用检测、访问令牌校验、风险撤销 |
| `auth/deps.py` | FastAPI 依赖：`require_principal`、`require_roles(...)` |
| `auth/routes.py` | `/auth/login|logout|refresh|me`、RBAC 与风控入口 |
| `tests/` | 服务层与 HTTP 端到端测试（可控时钟、多线程并发用例） |

## 2. 令牌与有效期

采用**不透明（opaque）随机令牌**而不是自包含 JWT：令牌本身无意义，服务端只保存其
SHA-256 哈希。这样登出 / 风控可以**立即**让令牌失效（自包含 JWT 在到期前无法真正
撤回，必须再配一张吊销表，等价于又回到了服务端状态）。

| 令牌 | Cookie | 默认有效期 | 存储 |
| --- | --- | --- | --- |
| 访问令牌 `at_...` | `sid_at` | **15 分钟** | 哈希存于当前 `Session` |
| 刷新令牌 `rt_...` | `sid_rt` | **14 天** | 哈希存于 `RefreshTokenRecord` |

其他时效：

- `idle_timeout_seconds`（默认 7 天）：会话无活动超过该时长，下次使用时惰性撤销。

Cookie 属性：`HttpOnly`（JS 不可读，缓解 XSS 窃取）、`SameSite=Lax`、`Path=/`；
`Secure` 由 `cookie_secure` 控制，生产环境（HTTPS）应置为 `true`。

## 3. 刷新令牌轮换与复用检测

### 3.1 单链轮换

每次刷新成功后：

1. 发放一对**新**的访问令牌 + 新刷新令牌；
2. 旧刷新令牌状态 `ACTIVE -> ROTATED`，记录 `rotated_at` 与后继 `successor_jti`，
   形成一条单链；
3. 旧访问令牌立即被新令牌取代。

旧刷新令牌**不能**再换到新令牌，除非落在下面的并发宽限规则内。

### 3.2 复用判定（疑似泄露 => 家族撤销）

当一张已经 `ROTATED` 的刷新令牌再次出现：

- **超过** `rotation_grace_seconds`（默认 30 秒）：判定为凭证泄露
  （`refresh_token_reuse`），**撤销整条会话家族**——会话标志置为撤销、访问令牌
  失效、家族内所有刷新令牌置为 `REVOKED`，对外返回 `token_reuse_detected`。
  之后该家族任何凭证都会得到 `session_revoked`。
- **在宽限窗口内**：视为客户端的并发刷新 / 响应丢失重试（见 3.3）。

### 3.3 并发刷新的工程取舍（重点）

刷新令牌在网络上可能被"几乎同时"提交两次：客户端超时重试、双击、多标签页、
移动网络重发等。若把任何旧令牌重现都判成复用，这些**完全合法**的行为会把用户
踢下线。本项目的取舍：

- 宽限窗口内旧令牌重现时，沿 `successor_jti` 链走到当前唯一的 `ACTIVE` 链头，
  从链头继续正常轮换。所有并发请求都能成功换到可用凭证，链始终保持单一头部，
  **不会误判复用、不会撤销会话**。
- 代价：窗口内若攻击者恰好也拿到旧令牌，同样会被接受。因此窗口只应略大于合理的
  请求/重试耗时（默认 **30s**，可通过 `rotation_grace_seconds` 调整），而窗口外的
  复用**一定**会被发现并完成家族撤销。
- 另一处刻意取舍：会话只保留最新一枚访问令牌，宽限重放会把链头再轮换一次，较早
  响应里的访问令牌会被更新的令牌取代。浏览器中多个响应写的是**同一个 Cookie 名**，
  最终留下的就是最新令牌，用户不掉线；持有旧响应的一方用其刷新令牌在窗口内可沿链
  自愈。换取的是更简单的服务端状态（不需要为一个会话维护多枚有效访问令牌）。

测试 `test_concurrent_refresh_threads_all_succeed` 用 8 个线程同时用同一枚旧
刷新令牌刷新，断言无一被误判；`test_concurrent_refresh_within_grace_does_not_logout`
断言窗口内沿链自愈、会话存活；`test_reuse_outside_grace_revokes_entire_family`
断言窗口外复用立即撤销家族。

## 4. 权限模型（RBAC）与拒绝原因

- 登录后得到 `Principal(user_id, username, roles, session_id)`。
- `require_principal`：只要求已认证。
- `require_roles("admin")` / `require_roles("member")`：要求拥有所列角色中至少一个。
- 演示用户：`alice`（`member`）、`admin`（`admin` + `member`）。

拒绝原因**可区分**：未认证统一 `401` 并携带具体错误码；已认证但角色不足为
`403 forbidden`。错误响应体形如 `{"error": "<code>"}`，**不含**令牌、哈希、
内部状态等任何细节；判定依据只写服务端日志。

| 场景 | HTTP | `error` 码 |
| --- | --- | --- |
| 未携带访问令牌（匿名） | 401 | `not_authenticated` |
| 访问令牌无法识别 / 伪造 | 401 | `invalid_token` |
| 访问令牌过期 | 401 | `access_token_expired` |
| 刷新令牌过期 | 401 | `refresh_token_expired` |
| 会话已撤销（登出 / 风控 / 空闲超时） | 401 | `session_revoked` |
| 刷新令牌窗口外复用（已家族撤销） | 401 | `token_reuse_detected` |
| 用户名或口令错误（二者同码，防账号枚举） | 401 | `invalid_credentials` |
| 已认证但权限不足 | 403 | `forbidden` |

日志只记录**输入与判定依据**：用户名（输入）、会话 id / jti 的前 8 位、哈希指纹
前 8 位、令牌状态、相对宽限窗口的 `age`、`basis=...`。测试
`test_no_token_values_leak_in_logs` 断言完整令牌明文绝不会出现在日志里。

## 5. HTTP 入口

| 方法 路径 | 说明 |
| --- | --- |
| `POST /auth/login` | 体 `{"username","password"}`，成功 `Set-Cookie: sid_at, sid_rt` |
| `POST /auth/logout` | 幂等；撤销家族并清除 Cookie，重复/无 Cookie/无法识别均返回 200 |
| `POST /auth/refresh` | 用 `sid_rt` 轮换，成功回写两枚新 Cookie |
| `GET  /auth/me` | 已认证可读，返回身份与角色 |
| `GET  /member/area` | 需要 `member` |
| `GET  /admin/users` | 需要 `admin` |
| `POST /admin/sessions/{session_id}/revoke` | 需要 `admin`；风控撤销目标会话，幂等 |

## 6. 配置项（`auth/config.py: AuthConfig`）

| 配置 | 默认 | 含义 |
| --- | --- | --- |
| `access_token_ttl` | `900`（15 分钟） | 访问令牌有效期（秒） |
| `refresh_token_ttl` | `1209600`（14 天） | 刷新令牌有效期（秒） |
| `rotation_grace_seconds` | `30` | 并发刷新宽限窗口；越界复用即家族撤销 |
| `idle_timeout_seconds` | `604800`（7 天） | 会话空闲超时，惰性撤销 |
| `cookie_secure` | `False` | 生产 HTTPS 下设为 `True` |
| `cookie_samesite` | `"lax"` | Cookie SameSite 策略 |
| `cookie_path` | `"/"` | Cookie Path |

`AuthService(store, config=..., clock=...)` 的 `clock` 为可注入时钟，仅用于测试
中确定性地"快进"时间。

> 演示工程口令以 SHA-256 存储仅为简化；生产请改用 bcrypt / argon2 加盐慢哈希，
> 存储层换成带持久化与事务的数据库，并在 HTTPS 下把 `cookie_secure` 打开。

## 7. 本地验证

```bash
# 安装依赖
uv sync

# 运行全部测试（33 个用例：服务层 + HTTP 端到端）
uv run pytest

# 查看每个用例打印的"输入 + 判定依据"日志
uv run pytest --log-cli-level=INFO

# 启动服务
uv run python main.py
```

手动验证（另开终端）：

```bash
BASE=http://127.0.0.1:8000
JAR=/tmp/cookies.txt; rm -f $JAR

# 匿名 -> 401 not_authenticated
curl -i $BASE/auth/me

# 登录（Cookie 自动存入 cookie jar）
curl -i -c $JAR -X POST $BASE/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice-pass"}'

# 已登录 -> 200
curl -s -b $JAR $BASE/auth/me

# alice 访问管理员入口 -> 403 forbidden
curl -s -b $JAR $BASE/admin/users

# 刷新轮换
curl -i -b $JAR -c $JAR -X POST $BASE/auth/refresh

# 登出（重复执行均 200，幂等）
curl -s -b $JAR -c $JAR -X POST $BASE/auth/logout
curl -s -b $JAR -X POST $BASE/auth/logout

# 登出后旧凭证 -> 401 session_revoked
curl -s -b $JAR $BASE/auth/me
```

观察服务端日志可以看到每次判定的 `basis`，例如：

```
INFO auth.service: login accepted input_user=alice session=6ed6f025 basis=password_verified
INFO auth.service: rotation ok session=... old_jti=... new_jti=... basis=normal_rotation
WARNING auth.service: refresh REUSE DETECTED ... age=3.0s basis=rotated_token_outside_grace family_revoked
```
