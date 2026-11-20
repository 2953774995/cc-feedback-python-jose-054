#!/usr/bin/env python3
"""验收探针：JWS 批量解析与算法拒绝（6 条契约）。token 现场签发，离线校验。"""
import sys, time, json, base64
from pathlib import Path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
RESULTS = []

def probe(name):
    def deco(fn):
        try:
            fn()
        except AssertionError as exc:
            RESULTS.append((name, False, str(exc) or "断言失败"))
        except Exception as exc:
            RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        else:
            RESULTS.append((name, True, ""))
        return fn
    return deco

def api():
    from jose.audit import audit_tokens
    return audit_tokens

KEY = "k" * 32
NOW = 1794960000  # 2026-11-18T00:00:00Z

def token(claims=None, key=KEY, alg="HS256"):
    from jose import jwt
    body = dict(claims or {})
    body.setdefault("iss", "https://idp.example.com")
    body.setdefault("aud", "gateway")
    body.setdefault("exp", NOW + 3600)
    body.setdefault("iat", NOW - 60)
    return jwt.encode(body, key, algorithm=alg)

def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")

@probe("P01 批量入口与合规 token")
def p01():
    fn = api(); out = fn([token()], key=KEY, allowed_algs=["HS256"], now=NOW,
                        expected_iss="https://idp.example.com", expected_aud="gateway")
    assert hasattr(out, "items") and hasattr(out, "stats"), "需返回 items 与 stats"
    item = out.items[0]
    for f in ("index", "ok", "reason", "alg", "iss", "aud", "exp", "issues"):
        assert f in item, f"item 缺字段 {f}"
    assert item["ok"] and item["reason"] == "ok", f"合规 token 应 ok，实际 {item['reason']}"
    assert item["alg"] == "HS256" and item["exp"] == NOW + 3600

@probe("P02 签名错误")
def p02():
    fn = api(); item = fn([token(key="wrong-key-wrong-key-wrong-key-12")], key=KEY,
                          allowed_algs=["HS256"], now=NOW).items[0]
    assert item["reason"] == "bad_signature", f"应为 bad_signature，实际 {item['reason']}"

@probe("P03 alg 不在白名单（含 none）")
def p03():
    fn = api()
    none_tok = b64u(b'{"alg":"none","typ":"JWT"}') + "." + b64u(json.dumps({"iss": "x"}).encode()) + "."
    out = fn([none_tok, token()], key=KEY, allowed_algs=["HS256"], now=NOW)
    assert out.items[0]["reason"] == "alg_rejected", f"none 应被拒，实际 {out.items[0]['reason']}"
    assert out.items[0]["alg"] == "none" and out.items[1]["ok"]

@probe("P04 过期与 iss/aud 不符")
def p04():
    fn = api()
    out = fn([token({"exp": NOW - 30}), token({"iss": "https://evil.example.com"}),
              token({"aud": "other"})], key=KEY, allowed_algs=["HS256"], now=NOW,
             expected_iss="https://idp.example.com", expected_aud="gateway")
    assert out.items[0]["reason"] == "expired", f"应为 expired，实际 {out.items[0]['reason']}"
    assert out.items[1]["reason"] == "wrong_iss", f"应为 wrong_iss，实际 {out.items[1]['reason']}"
    assert out.items[2]["reason"] == "wrong_aud", f"应为 wrong_aud，实际 {out.items[2]['reason']}"

@probe("P05 结构损坏隔离")
def p05():
    fn = api(); out = fn(["abc", "a.b.c.d", token()], key=KEY, allowed_algs=["HS256"], now=NOW)
    assert out.items[0]["reason"] == "malformed", f"应为 malformed，实际 {out.items[0]['reason']}"
    assert out.items[1]["reason"] == "malformed", f"四段应 malformed，实际 {out.items[1]['reason']}"
    assert out.items[2]["ok"], "坏 token 之后应继续"

@probe("P06 统计、空输入与批量性能")
def p06():
    fn = api(); good = token()
    out = fn([good, "junk", token({"exp": NOW - 1})], key=KEY, allowed_algs=["HS256"], now=NOW)
    st = out.stats
    assert st["ok"] == 1 and st["bad"] == 2, f"ok/bad 不对：{st}"
    assert st["by_reason"].get("expired") == 1 and st["by_reason"].get("malformed") == 1, st["by_reason"]
    empty = fn([], key=KEY); assert empty.items == [] and empty.stats["ok"] == 0, "空输入应返回空结构"
    recs = [good] * 300
    t0 = time.perf_counter(); out2 = fn(recs, key=KEY, allowed_algs=["HS256"], now=NOW)
    cost = time.perf_counter() - t0
    assert len(out2.items) == 300 and cost < 3.0, f"300 条耗时 {cost:.2f}s 超过 3s"

def main():
    print("=" * 60); print("验收探针：JWS 批量解析与算法拒绝（6 条契约）"); print("=" * 60)
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    for name, ok, detail in RESULTS:
        print(f"PASS  {name}" if ok else f"FAIL  {name}\n      {detail}")
    print("-" * 60); print(f"探针结果：{passed}/{len(RESULTS)} 通过")
    return 0 if passed == len(RESULTS) else 1

if __name__ == "__main__":
    sys.exit(main())
