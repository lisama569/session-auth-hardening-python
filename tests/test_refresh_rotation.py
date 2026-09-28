"""刷新令牌轮换、并发刷新宽限与复用检测。"""

import threading

from app.config import Settings


def _login_service(env, username="alice", password="alice123"):
    issued = env.service.login(username, password)
    return issued


def test_rotation_retires_old_refresh_token_after_grace(env):
    issued = _login_service(env)
    r1 = env.service.refresh(issued.refresh_token)
    assert r1.refresh_token != issued.refresh_token

    # 正常连续轮换：新令牌可继续使用
    r2 = env.service.refresh(r1.refresh_token)
    assert r2.refresh_token != r1.refresh_token

    # 超过宽限窗口后再次出示最老的令牌 -> 复用 -> 整条会话撤销
    env.clock.advance(env.settings.refresh_grace_window_seconds + 1)
    try:
        env.service.refresh(issued.refresh_token)
        assert False, "应当判定为复用"
    except Exception as exc:
        assert exc.code.value == "refresh_token_reused"

    # 最新令牌也必须全部失效（族撤销）
    try:
        env.service.refresh(r2.refresh_token)
        assert False, "会话应已被撤销"
    except Exception as exc:
        assert exc.code.value == "session_revoked"


def test_concurrent_refresh_within_grace_is_not_reuse(env):
    """几乎同时发生的并发刷新：只有一次真正轮换，所有请求拿到同一对令牌。"""
    issued = _login_service(env)
    results: list = []
    errors: list = []
    barrier = threading.Barrier(5)

    def worker():
        try:
            barrier.wait()
            results.append(env.service.refresh(issued.refresh_token))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == [], f"并发刷新不应误伤合法请求: {errors}"
    assert len(results) == 5
    accesses = {r.access_token for r in results}
    refreshes = {r.refresh_token for r in results}
    assert accesses == {results[0].access_token}
    assert refreshes == {results[0].refresh_token}

    # 会话依然健康：并发结束后还能用最新令牌继续轮换
    next_issued = env.service.refresh(results[0].refresh_token)
    assert next_issued.refresh_token != results[0].refresh_token


def test_concurrent_replay_then_late_replay_is_reuse(env):
    """宽限内并发安全；宽限外同一旧令牌再出现即按泄露处置。"""
    issued = _login_service(env)

    first = env.service.refresh(issued.refresh_token)
    concurrent = env.service.refresh(issued.refresh_token)  # 宽限内
    assert concurrent.refresh_token == first.refresh_token

    env.clock.advance(env.settings.refresh_grace_window_seconds + 1)
    try:
        env.service.refresh(issued.refresh_token)
        assert False
    except Exception as exc:
        assert exc.code.value == "refresh_token_reused"

    # 第一次轮换出的新令牌也已随会话一起作废
    try:
        env.service.refresh(first.refresh_token)
        assert False
    except Exception as exc:
        assert exc.code.value == "session_revoked"


def test_reuse_after_full_chain_rotation_revokes_family(env):
    issued = _login_service(env)
    chain = [issued.refresh_token]
    current = issued
    for _ in range(3):
        current = env.service.refresh(current.refresh_token)
        chain.append(current.refresh_token)

    # 攻击者重放链上任一旧令牌（窗口外）-> 整个刷新族被撤销
    env.clock.advance(env.settings.refresh_grace_window_seconds + 1)
    try:
        env.service.refresh(chain[1])
        assert False
    except Exception as exc:
        assert exc.code.value == "refresh_token_reused"

    # 链上所有令牌都不可再用，原因可区分：会话级撤销
    for token in chain[2:]:
        try:
            env.service.refresh(token)
            assert False
        except Exception as exc:
            assert exc.code.value == "session_revoked"


def test_decision_basis_logged_without_token_plaintext(env, caplog):
    """单测日志能打印输入与判定依据，且不含令牌原文。"""
    issued = _login_service(env)
    env.service.refresh(issued.refresh_token)  # 第一次成功轮换，旧令牌变为 used
    env.clock.advance(env.settings.refresh_grace_window_seconds + 1)
    try:
        env.service.refresh(issued.refresh_token)  # 窗口外重放旧令牌 -> 复用
    except Exception:
        pass

    text = caplog.text
    assert "event=refresh" in text
    assert "reason=refresh_token_reused" in text, text
    assert issued.refresh_token not in text, "日志不得包含刷新令牌原文"
    # 只出现哈希短指纹
    assert "fp=" in text


def test_grace_window_is_configurable():
    """工程取舍必须可配置：更大的宽限窗口覆盖更长的网络重试。"""
    s = Settings(refresh_grace_window_seconds=30)
    assert s.refresh_grace_window_seconds == 30
