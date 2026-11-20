"""Batch admission audit for JWS tokens.

面向服务网格边车的批量准入场景：对一组 token 逐条判定签名有效性、
算法白名单、过期时间、issuer 与 audience，单条失败不影响后续条目，
并输出统一分类码与统计信息。

不改动 jose.jwt / jose.jws 的既有行为，仅复用其公开的密钥处理逻辑。
"""

import binascii
import json
import time
from collections import namedtuple

from jose import jws
from jose.utils import base64url_decode

DEFAULT_ALLOWED_ALGS = ["HS256", "HS384", "HS512"]

REASON_OK = "ok"
REASON_BAD_SIGNATURE = "bad_signature"
REASON_ALG_REJECTED = "alg_rejected"
REASON_EXPIRED = "expired"
REASON_WRONG_ISS = "wrong_iss"
REASON_WRONG_AUD = "wrong_aud"
REASON_MALFORMED = "malformed"

AuditResult = namedtuple("AuditResult", ["items", "stats"])


def audit_tokens(tokens, key, allowed_algs=None, expected_iss=None,
                 expected_aud=None, now=None):
    """批量审计 JWS token。

    Args:
        tokens (list): JWS 字符串列表。
        key: 验签密钥（同 jose.jws.verify 的 key 语义）。
        allowed_algs (list, optional): 允许的 alg 白名单，
            缺省为 ["HS256", "HS384", "HS512"]。
        expected_iss (str, optional): 期望的 issuer，传入时校验。
        expected_aud (str, optional): 期望的 audience，传入时校验。
        now (int, optional): 判定过期所用的 epoch 秒，缺省取当前时间。

    Returns:
        AuditResult: 含 items（逐条判定结果）与 stats（统计）。
    """
    allowed = set(allowed_algs) if allowed_algs is not None else set(DEFAULT_ALLOWED_ALGS)
    if now is None:
        now = int(time.time())

    items = []
    by_reason = {}
    ok_count = 0

    for index, token in enumerate(tokens):
        item = _audit_one(token, key, allowed, expected_iss, expected_aud, now)
        item["index"] = index
        items.append(item)
        by_reason[item["reason"]] = by_reason.get(item["reason"], 0) + 1
        if item["ok"]:
            ok_count += 1

    stats = {
        "ok": ok_count,
        "bad": len(items) - ok_count,
        "by_reason": by_reason,
    }
    return AuditResult(items=items, stats=stats)


def _new_item():
    return {
        "index": None,
        "ok": False,
        "reason": None,
        "alg": None,
        "iss": None,
        "aud": None,
        "exp": None,
        "issues": [],
    }


def _reject(item, reason, issue):
    item["reason"] = reason
    item["issues"].append(issue)
    return item


def _audit_one(token, key, allowed, expected_iss, expected_aud, now):
    item = _new_item()

    if isinstance(token, bytes):
        try:
            token = token.decode("utf-8")
        except UnicodeDecodeError:
            return _reject(item, REASON_MALFORMED, "token is not valid utf-8")
    if not isinstance(token, str):
        return _reject(item, REASON_MALFORMED, "token is not a string")

    segments = token.encode("utf-8").split(b".")
    if len(segments) != 3:
        return _reject(item, REASON_MALFORMED,
                       "expected 3 segments, got %d" % len(segments))
    header_segment, claims_segment, crypto_segment = segments
    signing_input = b".".join([header_segment, claims_segment])

    # 头部解析：失败即 malformed
    try:
        header_data = base64url_decode(header_segment)
        header = json.loads(header_data.decode("utf-8"))
        if not isinstance(header, dict):
            raise ValueError("header is not a json object")
    except (ValueError, TypeError, binascii.Error, UnicodeDecodeError):
        return _reject(item, REASON_MALFORMED, "invalid header segment")

    alg = header.get("alg")
    item["alg"] = alg

    # 算法白名单：alg=none 或未列入白名单一律拒绝，不降级为 malformed
    if alg not in allowed:
        return _reject(item, REASON_ALG_REJECTED,
                       "alg %r is not in the allowed list" % alg)

    # 载荷解析：失败即 malformed
    try:
        claims_data = base64url_decode(claims_segment)
        claims = json.loads(claims_data.decode("utf-8"))
        if not isinstance(claims, dict):
            raise ValueError("claims is not a json object")
    except (ValueError, TypeError, binascii.Error, UnicodeDecodeError):
        return _reject(item, REASON_MALFORMED, "invalid claims segment")

    item["iss"] = claims.get("iss")
    item["aud"] = claims.get("aud")
    item["exp"] = claims.get("exp")

    # 签名校验
    try:
        signature = base64url_decode(crypto_segment)
    except (TypeError, binascii.Error):
        return _reject(item, REASON_MALFORMED, "invalid crypto segment")

    try:
        keys = jws._get_keys(key)
        verified = jws._sig_matches_keys(keys, signing_input, signature, alg)
    except Exception:
        verified = False
    if not verified:
        return _reject(item, REASON_BAD_SIGNATURE, "signature verification failed")

    # 过期判定：exp <= now 视为过期
    exp = claims.get("exp")
    if exp is not None:
        try:
            if int(exp) <= now:
                return _reject(item, REASON_EXPIRED, "token is expired")
        except (TypeError, ValueError):
            return _reject(item, REASON_MALFORMED, "exp claim is not an integer")

    # issuer / audience 校验
    if expected_iss is not None and claims.get("iss") != expected_iss:
        return _reject(item, REASON_WRONG_ISS,
                       "issuer %r does not match %r" % (claims.get("iss"), expected_iss))

    if expected_aud is not None:
        aud = claims.get("aud")
        if isinstance(aud, list):
            matched = expected_aud in aud
        else:
            matched = aud == expected_aud
        if not matched:
            return _reject(item, REASON_WRONG_AUD,
                           "audience %r does not match %r" % (aud, expected_aud))

    item["ok"] = True
    item["reason"] = REASON_OK
    return item
