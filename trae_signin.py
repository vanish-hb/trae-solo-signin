r"""TRAE SOLO CN（TraeWork CN）每日签到自动领取脚本。

参考 workbuddy-auto-signin 的结构编写。凭据格式与签到接口系从 TRAE SOLO CN
桌面端（Electron）逆向所得，服务端或客户端改版可能失效。

工作原理：
  1. 读取本机 TRAE SOLO CN 桌面端登录后写入的凭据文件：
       Windows: %APPDATA%\TRAE SOLO CN\User\globalStorage\storage.json
       macOS  : ~/Library/Application Support/TRAE SOLO CN/User/globalStorage/storage.json
     取出键 iCubeAuthInfo://icube.cloudide 的加密串（base64，"dGMFEAAA" 开头）。
  2. 按 TRAE 内置 byteCrypto 方案解密（AES-128-CBC，密钥由 SHA-512 链派生，
     纯算法实现，无需调用客户端运行时）得到 userInfo.token。
  3. 调用签到接口：
       POST {endpoint}/trae/api/v2/ug/checkin_credits/status  查询签到状态
       POST {endpoint}/trae/api/v2/ug/checkin_credits/claim   领取今日积分
     请求头 Authorization: Cloud-IDE-JWT <token>
  4. token 自动续期（逆向自桌面端 oauth/marscode 链路）：
     当 token 剩余有效期不足 REFRESH_MARGIN_DAYS 天（或已过期）且本机
     客户端未在运行时，用 storage.json 里的 refreshToken +
     iCubeAuthInfo://icube-dc:<deviceId> 设备密钥对（EC P-256）签名调用
       POST {endpoint}/trae/api/v3/oauth/ExchangeToken
     换取新 token，并按 byteCrypto 原格式加密写回 storage.json。
     因此只要偶尔（半年内）成功跑过一次脚本，就无需打开客户端续命。

响应契约（逆向自桌面端 main.js）：
  - status: {"code":0, "enable":bool, "checked_in":bool, "credits":int, ...}
  - claim 成功: HTTP 200 且 code===0（或无 code 字段）
  - 今日已签: 业务 code 非 0（幂等，按"已签"处理）

任何模式下都不会打印令牌，可安全分享日志。

用法：
  python trae_signin.py auto           # 每日自动化：查状态 + 未签才领（默认）
  python trae_signin.py silent         # 同 auto，但结果写日志文件而非 stdout
  python trae_signin.py status         # 仅查签到状态（调试）
  python trae_signin.py claim          # 仅领取签到（调试，幂等）
  python trae_signin.py doctor         # 离线检查凭据可读性与格式，不联网
"""

import base64
import hashlib
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

DEFAULT_ENDPOINT = "https://api.trae.cn"
AUTH_KEY_SUFFIX = "iCubeAuthInfo://icube.cloudide"
TINYSTORAGE_REL = os.path.join("aha", "TinyStorage")
MACHINEID_FILE = "machineid"

# --- 自动续期常量（逆向自桌面端 oauth/marscode/request.js 与 product.json） ---
EXCHANGE_PATH = "/trae/api/v3/oauth/ExchangeToken"
# product.json → iCubeApp.authConfig.SOLO.stable
CLIENT_ID = os.environ.get("TRAE_CLIENT_ID") or "en1oxy7wnw8j9n"
# 客户端 appVersion 兜底值（运行时优先读 product.json 的 appVersion）
IDE_VERSION = "0.1.69"
REFRESH_MARGIN_DAYS = 3.0
DEVICE_KEY_PREFIX = "iCubeAuthInfo://icube-dc:"
# 服务端判定"刷新令牌失效需重新登录"的业务错误码
REFRESH_FATAL_CODES = {"20324", "20101", "20315", "20125", "20126", "20401", "20403"}

# 伪 HTTP 码：区分"没拿到响应"的两种原因
CODE_NO_NETWORK = -1    # 连不上/超时
CODE_BUDGET_OUT = -2    # 本次运行的时间预算已耗尽

REQUEST_TIMEOUT = 30
DEFAULT_BUDGET_SECONDS = 240.0
# 网络类失败退避（秒）：定时任务常在"刚开机/刚唤醒"时撞上网络未就绪，
# 5 秒重试没用，退避到分钟级才跨得过 WiFi 重连/VPN 拨通的窗口。
NETWORK_RETRY_DELAYS = (5, 15, 30, 60)
# 5xx 是服务端抖动，短促重试即可
SERVER_RETRY_DELAYS = (3, 10)

_started_at = None
_budget_seconds = DEFAULT_BUDGET_SECONDS

# ---------------------------------------------------------------------------
# TRAE byteCrypto 解密（逆向自 out/vs/base/common/byteCrypto.js）
# ---------------------------------------------------------------------------

# qoe ^ zoe → 64 字节 XOR 表（AES 版，suite=1）
_QOE = bytes([
    82, 9, 106, 213, 48, 54, 165, 56, 191, 64, 163, 158, 129, 243, 215, 251,
    124, 227, 57, 130, 155, 47, 255, 135, 52, 142, 67, 68, 196, 222, 233, 203,
    84, 123, 148, 50, 166, 194, 35, 61, 238, 76, 149, 11, 66, 250, 195, 78,
    8, 46, 161, 102, 40, 217, 36, 178, 118, 91, 162, 73, 109, 139, 209, 37,
])
_ZOE = bytes([
    31, 221, 168, 51, 136, 7, 199, 49, 177, 18, 16, 89, 39, 128, 236, 95,
    96, 81, 127, 169, 25, 181, 74, 13, 45, 229, 122, 159, 147, 201, 156, 239,
    160, 224, 59, 77, 174, 42, 245, 176, 200, 235, 187, 60, 131, 83, 153, 97,
    23, 43, 4, 126, 186, 119, 214, 38, 225, 105, 20, 99, 85, 33, 12, 125,
])
_XOR64 = bytes(a ^ b for a, b in zip(_QOE, _ZOE))

# 密文头 6 字节：'t','c',5,16,0,0（base64 后即 "dGMFEAAA"）
_HEADER_AES = bytes([116, 99, 5, 16, 0, 0])
_SEED_LEN = 32      # pv：随机种子长度
_CHECKSUM_LEN = 64  # vh：SHA-512 校验长度


class AuthError(Exception):
    """凭据边界上只允许固定的、不含敏感信息的报错。"""

    REASONS = {
        "NO_AUTH": "未找到 TRAE 登录凭据，请先在本机登录 TRAE SOLO CN 桌面端",
        "INVALID_FORMAT": "登录凭据格式无效，请检查客户端版本",
        "UNSUPPORTED_ENVELOPE": "尚不支持此加密凭据格式，请更新脚本",
        "NO_SESSION": "本地未找到有效登录会话，请先登录 TRAE SOLO CN",
        "TOKEN_EXPIRED": "登录令牌已过期，请打开 TRAE SOLO CN 客户端重新登录一次",
        "DECRYPT_FAILED": "加密凭据解密失败，请重新登录客户端",
    }

    def __init__(self, reason, result="AUTH_ERROR"):
        self.reason = reason
        self.result = result
        super().__init__(self.REASONS.get(reason, reason))

    def output(self):
        return {"result": self.result, "reason": self.reason,
                "report": str(self), "needs_attention": True}


def _sha512(data):
    return hashlib.sha512(data).digest()


def _derive_key_iv(seed):
    """byteCrypto.Moe：SHA-512 链式派生 AES-128 密钥与 IV。

    n[0:64]   = SHA512(seed)
    n[64:128] = qoe^zoe XOR 表
    c = SHA512(n); n[0:64] = c
    key = n[0:16]; iv = n[16:32]
    """
    n = bytearray(128)
    n[0:64] = _sha512(seed)
    n[64:128] = _XOR64
    c = _sha512(bytes(n))
    n[0:64] = c
    return bytes(n[0:16]), bytes(n[16:32])


def _aes_cbc_decrypt(key, iv, ciphertext):
    """AES-128-CBC 解密 + PKCS7 去填充。优先第三方库，退回纯 Python 实现。"""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        padded = dec.update(ciphertext) + dec.finalize()
    except ImportError:
        try:
            from Crypto.Cipher import AES
            padded = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
        except ImportError:
            padded = _pure_aes128_cbc_decrypt(key, iv, ciphertext)
    if not padded:
        raise AuthError("DECRYPT_FAILED")
    padlen = padded[-1]
    if not (1 <= padlen <= 16) or padded[-padlen:] != bytes([padlen]) * padlen:
        raise AuthError("DECRYPT_FAILED")
    return padded[:-padlen]


_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]
_INV_SBOX = [0] * 256
for _i, _v in enumerate(_SBOX):
    _INV_SBOX[_v] = _i


def _xtime(a):
    a <<= 1
    return (a ^ 0x1b) & 0xFF if a & 0x100 else a


def _mul(a, b):
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = _xtime(a)
    return p


def _expand_key(key):
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [_SBOX[b] for b in t]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [w[4 * r:4 * r + 4] for r in range(11)]


def _dec_block(block, round_keys):
    """解密单个 16 字节块（InvShiftRows + InvSubBytes + AddRoundKey 循环）。"""
    s = [[block[r + 4 * c] for c in range(4)] for r in range(4)]

    def add_round_key(s, rk):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= rk[c][r]

    add_round_key(s, round_keys[10])
    for rnd in range(9, -1, -1):
        for r in range(1, 4):          # InvShiftRows
            s[r] = s[r][-r:] + s[r][:-r]
        for r in range(4):             # InvSubBytes
            for c in range(4):
                s[r][c] = _INV_SBOX[s[r][c]]
        add_round_key(s, round_keys[rnd])
        if rnd > 0:                    # InvMixColumns
            for c in range(4):
                a = [s[r][c] for r in range(4)]
                s[0][c] = _mul(a[0], 14) ^ _mul(a[1], 11) ^ _mul(a[2], 13) ^ _mul(a[3], 9)
                s[1][c] = _mul(a[0], 9) ^ _mul(a[1], 14) ^ _mul(a[2], 11) ^ _mul(a[3], 13)
                s[2][c] = _mul(a[0], 13) ^ _mul(a[1], 9) ^ _mul(a[2], 14) ^ _mul(a[3], 11)
                s[3][c] = _mul(a[0], 11) ^ _mul(a[1], 13) ^ _mul(a[2], 9) ^ _mul(a[3], 14)
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _pure_aes128_cbc_decrypt(key, iv, ciphertext):
    """纯 Python AES-128-CBC 解密（凭据很小，性能足够）。"""
    if len(ciphertext) % 16 != 0:
        raise AuthError("DECRYPT_FAILED")
    round_keys = _expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i + 16]
        dec = _dec_block(block, round_keys)
        out.extend(a ^ b for a, b in zip(dec, prev))
        prev = block
    return bytes(out)


def trae_decrypt(b64_value):
    """解密 TRAE 桌面端写出的加密串，返回明文字节串。

    密文布局：header(6) + seed(32) + AES-CBC( checksum(64) + data )
    """
    if not isinstance(b64_value, str) or not b64_value:
        raise AuthError("INVALID_FORMAT")
    try:
        blob = base64.b64decode(b64_value, validate=True)
    except Exception:
        raise AuthError("INVALID_FORMAT") from None
    if len(blob) < 6 + _SEED_LEN + 16:
        raise AuthError("INVALID_FORMAT")
    if blob[:6] != _HEADER_AES:
        raise AuthError("UNSUPPORTED_ENVELOPE")
    seed = blob[6:6 + _SEED_LEN]
    key, iv = _derive_key_iv(seed)
    padded = _aes_cbc_decrypt(key, iv, blob[6 + _SEED_LEN:])
    if len(padded) <= _CHECKSUM_LEN:
        raise AuthError("DECRYPT_FAILED")
    checksum, data = padded[:_CHECKSUM_LEN], padded[_CHECKSUM_LEN:]
    if _sha512(data) != checksum:
        raise AuthError("DECRYPT_FAILED")
    return data


def _enc_block(block, round_keys):
    """加密单个 16 字节块（AddRoundKey + SubBytes + ShiftRows + MixColumns）。"""
    s = [[block[r + 4 * c] for c in range(4)] for r in range(4)]

    def add_round_key(rk):
        for c in range(4):
            for r in range(4):
                s[r][c] ^= rk[c][r]

    add_round_key(round_keys[0])
    for rnd in range(1, 11):
        for r in range(4):              # SubBytes
            for c in range(4):
                s[r][c] = _SBOX[s[r][c]]
        for r in range(1, 4):           # ShiftRows（行左移 r）
            s[r] = s[r][r:] + s[r][:r]
        add_round_key(round_keys[rnd])
        if rnd < 10:                    # MixColumns
            for c in range(4):
                a = [s[r][c] for r in range(4)]
                s[0][c] = _mul(a[0], 2) ^ _mul(a[1], 3) ^ a[2] ^ a[3]
                s[1][c] = a[0] ^ _mul(a[1], 2) ^ _mul(a[2], 3) ^ a[3]
                s[2][c] = a[0] ^ a[1] ^ _mul(a[2], 2) ^ _mul(a[3], 3)
                s[3][c] = _mul(a[0], 3) ^ a[1] ^ a[2] ^ _mul(a[3], 2)
    return bytes(s[r][c] for c in range(4) for r in range(4))


def _pure_aes128_cbc_encrypt(key, iv, padded):
    """纯 Python AES-128-CBC 加密（入参需已按 PKCS7 填充）。"""
    if len(padded) % 16 != 0:
        raise ValueError("plaintext must be padded to block size")
    round_keys = _expand_key(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(padded), 16):
        cur = _enc_block(bytes(a ^ b for a, b in zip(padded[i:i + 16], prev)),
                         round_keys)
        out.extend(cur)
        prev = cur
    return bytes(out)


def _aes_cbc_encrypt(key, iv, plaintext):
    """AES-128-CBC 加密 + PKCS7 填充。优先第三方库，退回纯 Python 实现。"""
    padlen = 16 - len(plaintext) % 16
    padded = plaintext + bytes([padlen]) * padlen
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
        return enc.update(padded) + enc.finalize()
    except ImportError:
        try:
            from Crypto.Cipher import AES
            return AES.new(key, AES.MODE_CBC, iv).encrypt(padded)
        except ImportError:
            return _pure_aes128_cbc_encrypt(key, iv, padded)


def trae_encrypt(data):
    """按 TRAE byteCrypto 方案加密，返回与客户端 storage.json 相同格式的 base64 串。"""
    seed = os.urandom(_SEED_LEN)
    key, iv = _derive_key_iv(seed)
    padded = _sha512(data) + data
    blob = _HEADER_AES + seed + _aes_cbc_encrypt(key, iv, padded)
    return base64.b64encode(blob).decode("ascii")


# ---------------------------------------------------------------------------
# ECDSA P-256 设备签名（DeviceProof，逆向自 oauth/marscode/util.js 的 _Te()）
# ---------------------------------------------------------------------------

_P256_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
_P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
_P256_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
_P256_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5


def _ec_add(P, Q):
    if P is None:
        return Q
    if Q is None:
        return P
    x1, y1 = P
    x2, y2 = Q
    if x1 == x2 and (y1 + y2) % _P256_P == 0:
        return None
    if P == Q:
        lam = (3 * x1 * x1 - 3) * pow(2 * y1, _P256_P - 2, _P256_P) % _P256_P
    else:
        lam = (y2 - y1) * pow((x2 - x1) % _P256_P, _P256_P - 2, _P256_P) % _P256_P
    x3 = (lam * lam - x1 - x2) % _P256_P
    y3 = (lam * (x1 - x3) - y1) % _P256_P
    return (x3, y3)


def _ec_mul(k, P):
    R = None
    while k:
        if k & 1:
            R = _ec_add(R, P)
        P = _ec_add(P, P)
        k >>= 1
    return R


def _der_children(blob):
    """迭代解析顶层 DER TLV，返回 [(tag, value_bytes), ...]。"""
    out = []
    i = 0
    while i < len(blob):
        tag = blob[i]
        i += 1
        ln = blob[i]
        i += 1
        if ln & 0x80:
            nbytes = ln & 0x7F
            ln = int.from_bytes(blob[i:i + nbytes], "big")
            i += nbytes
        out.append((tag, blob[i:i + ln]))
        i += ln
    return out


def _parse_pkcs8_ec_privkey(pem):
    """从 PKCS8 EC PEM 中提取 32 字节私钥标量（整数）。"""
    b64 = "".join(l for l in pem.splitlines() if "-----" not in l)
    der = base64.b64decode(b64)
    # 外层 SEQUENCE 的内容体
    outer = _der_children(der)
    body = None
    for tag, val in outer:
        if tag == 0x30 and len(val) > 2:
            body = val
            break
    if body is None:
        raise AuthError("INVALID_FORMAT")
    # SEQUENCE[ INTEGER(version), SEQUENCE(alg), OCTET STRING(inner) ]
    inner = None
    for tag, val in _der_children(body):
        if tag == 0x04:
            inner = val
            break
    if inner is None:
        raise AuthError("INVALID_FORMAT")
    # inner 是 ECPrivateKey DER：SEQUENCE[ INTEGER(1), OCTET STRING(d), [1] ]
    ecbody = None
    for tag, val in _der_children(inner):
        if tag == 0x30:
            ecbody = val
            break
    if ecbody is None:
        raise AuthError("INVALID_FORMAT")
    for tag, val in _der_children(ecbody):
        if tag == 0x04 and len(val) == 32:
            return int.from_bytes(val, "big")
    raise AuthError("INVALID_FORMAT")


def _ecdsa_p256_sign(d, message):
    """SHA-256 + ECDSA P-256 签名（随机 k），返回 (r, s)。"""
    z = int.from_bytes(hashlib.sha256(message).digest(), "big")
    while True:
        k = int.from_bytes(os.urandom(32), "big") % _P256_N
        if k == 0:
            continue
        R = _ec_mul(k, (_P256_GX, _P256_GY))
        r = R[0] % _P256_N
        if r == 0:
            continue
        s = pow(k, -1, _P256_N) * (z + r * d) % _P256_N
        if s == 0:
            continue
        return r, s


def _int_to_der(i):
    b = i.to_bytes((i.bit_length() + 7) // 8 or 1, "big")
    if b[0] & 0x80:
        b = b"\x00" + b
    return bytes([0x02, len(b)]) + b


def _sig_to_der(r, s):
    seq = _int_to_der(r) + _int_to_der(s)
    return bytes([0x30, len(seq)]) + seq


def _sig_to_raw(r, s):
    """IEEE-P1363 裸格式（r||s 各 32 字节）。"""
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def sign_device_proof(private_key_pem, client_id, refresh_token, raw_format=False):
    """复刻桌面端 _Te()：对 "POST\\n<path>\\n<ClientID>\\n<RefreshToken>\\n<ts>\\n<nonce>"
    （换行符连接，源码中 join(`\\n`) 被压缩成 join(<换行>)）做 SHA-256 + ECDSA-P256 签名。"""
    ts = int(time.time())
    nonce = os.urandom(16).hex()
    message = "\n".join(["POST", EXCHANGE_PATH, client_id, refresh_token,
                         str(ts), nonce]).encode("utf-8")
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        key = load_pem_private_key(private_key_pem.encode("ascii"), password=None)
        der = key.sign(message, ec.ECDSA(hashes.SHA256()))
        if raw_format:
            # DER: SEQUENCE[ INTEGER(r), INTEGER(s) ] → 裸 64 字节
            seq = _der_children(der)[0][1]
            parts = _der_children(seq)
            sig = _sig_to_raw(int.from_bytes(parts[0][1], "big"),
                              int.from_bytes(parts[1][1], "big"))
        else:
            sig = der
    except ImportError:
        d = _parse_pkcs8_ec_privkey(private_key_pem)
        r, s = _ecdsa_p256_sign(d, message)
        sig = _sig_to_raw(r, s) if raw_format else _sig_to_der(r, s)
    return {"Signature": base64.b64encode(sig).decode("ascii"),
            "Timestamp": ts,
            "Nonce": nonce}


# ---------------------------------------------------------------------------
# 凭据探测与加载
# ---------------------------------------------------------------------------

def find_auth_file():
    """按平台探测 TRAE 桌面端写出的 storage.json，支持环境变量覆盖。

    返回 (path_or_None, looked_in)。
    """
    override = os.environ.get("TRAE_AUTH_FILE")
    if override:
        return (override if os.path.exists(override) else None), [override]
    home = os.path.expanduser("~")
    roaming = os.environ.get("APPDATA") or os.path.join(home, "AppData", "Roaming")
    rel = os.path.join("User", "globalStorage", "storage.json")
    candidates = [
        os.path.join(roaming, "TRAE SOLO CN", rel),                                  # Windows SOLO
        os.path.join(roaming, "Trae CN", rel),                                       # Windows IDE
        os.path.join(home, "Library", "Application Support", "TRAE SOLO CN", rel),   # macOS
        os.path.join(home, "Library", "Application Support", "Trae CN", rel),
        os.path.join(home, ".config", "TRAE SOLO CN", rel),                          # Linux 猜测
    ]
    for c in candidates:
        if os.path.exists(c):
            return c, candidates
    return None, candidates


def load_storage(auth_file):
    """带重试读取 storage.json（客户端刷新 token 时可能短暂独占文件）。"""
    last = None
    for i in range(3):
        try:
            with open(auth_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except PermissionError as e:
            last = e
            if i < 2:
                time.sleep(2)
    raise last


def load_session(auth_file):
    """从 storage.json 解出 {token, user_id, expired_at, device_id}。"""
    storage = load_storage(auth_file)
    if not isinstance(storage, dict) or AUTH_KEY_SUFFIX not in storage:
        raise AuthError("NO_SESSION")
    raw = trae_decrypt(storage[AUTH_KEY_SUFFIX])
    try:
        info = json.loads(raw.decode("utf-8"))
    except Exception:
        raise AuthError("INVALID_FORMAT") from None
    if not isinstance(info, dict) or not info.get("token"):
        raise AuthError("NO_SESSION")
    if info.get("account", {}).get("scope") != "marscode":
        # 桌面端用非 Trae 账号（如字节 SSO）登录时无签到活动
        raise AuthError("NO_SESSION")

    # 设备 ID 存于 aha/TinyStorage，同样加密；取不到不影响签到
    device_id = ""
    data_dir = os.path.dirname(os.path.dirname(os.path.dirname(auth_file)))
    tinystorage = os.path.join(data_dir, TINYSTORAGE_REL)
    try:
        with open(tinystorage, "r", encoding="utf-8") as f:
            ts = json.load(f)
        dev_raw = trae_decrypt(ts.get("tiny_storage_data", {}).get("aha.device.device_id", ""))
        dev = json.loads(dev_raw.decode("utf-8"))
        device_id = dev.get("device_id_str") or dev.get("device_id") or ""
    except Exception:
        pass

    # 设备密钥对（自动续期签名用）：iCubeAuthInfo://icube-dc:<deviceId>
    keypair, device_key_id = None, ""
    for k in storage:
        if isinstance(k, str) and k.startswith(DEVICE_KEY_PREFIX):
            device_key_id = k[len(DEVICE_KEY_PREFIX):]
            try:
                kp = json.loads(trae_decrypt(storage[k]).decode("utf-8"))
                if kp.get("privateKeyPEM") and kp.get("publicKeyPEM"):
                    keypair = kp
            except Exception:
                pass
            break

    # MachineID：与客户端一致取 storage.json 的 telemetry.machineId（64 位 hex）
    machine_id = str(storage.get("telemetry.machineId") or "")
    if not machine_id:
        try:
            with open(os.path.join(data_dir, MACHINEID_FILE), "r", encoding="utf-8") as f:
                machine_id = f.read().strip()
        except Exception:
            pass

    return {
        "token": info["token"],
        "user_id": info.get("userId", ""),
        "expired_at": info.get("expiredAt", ""),
        "refresh_token": info.get("refreshToken") or "",
        "refresh_expired_at": info.get("refreshExpiredAt", ""),
        "device_id": device_id,
        "device_key_id": device_key_id or device_id,
        "machine_id": machine_id,
        "keypair": keypair,
        "info": info,
    }


def check_token_freshness(session):
    """token 过期时给出可操作的提示（客户端打开时会自动刷新，无需手动处理）。"""
    expired_at = session.get("expired_at") or ""
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})", expired_at)
    if not m:
        return
    try:
        exp = datetime(*map(int, m.groups()))
    except ValueError:
        return
    if exp < datetime.utcnow():
        raise AuthError("TOKEN_EXPIRED")


# ---------------------------------------------------------------------------
# token 自动续期（ExchangeToken，逆向自 oauth/marscode）
# ---------------------------------------------------------------------------

def _iso_ms(ms):
    """毫秒时间戳 → 客户端同款 ISO 字符串（如 2026-10-19T06:31:42.009Z）。"""
    if not ms:
        return ""
    secs, msec = divmod(int(ms), 1000)
    return datetime.utcfromtimestamp(secs).strftime("%Y-%m-%dT%H:%M:%S") + ".%03dZ" % msec


def _client_running():
    """粗略检测 TRAE 客户端是否在运行（避免与其并发写凭据文件）。"""
    import subprocess
    try:
        if os.name == "nt":
            out = subprocess.run(["tasklist", "/FO", "CSV"], capture_output=True,
                                 timeout=15).stdout.decode("utf-8", "replace").lower()
        else:
            out = subprocess.run(["ps", "-e"], capture_output=True,
                                 timeout=15).stdout.decode("utf-8", "replace").lower()
        return "trae" in out
    except Exception:
        return False


def _token_expires_soon(session, margin_days=REFRESH_MARGIN_DAYS):
    """token 剩余有效期是否不足 margin_days（无法解析过期时间时按临期处理）。"""
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})",
                 session.get("expired_at") or "")
    if not m:
        return True
    try:
        exp = datetime(*map(int, m.groups()))
    except ValueError:
        return True
    return (exp - datetime.utcnow()).total_seconds() < margin_days * 86400


def _ide_version():
    """客户端 appVersion（product.json 根部，与包 version 不同，如 0.1.69）。"""
    if os.environ.get("TRAE_IDE_VERSION"):
        return os.environ["TRAE_IDE_VERSION"]
    candidates = []
    if os.name == "nt":
        env = os.environ
        candidates = [
            os.path.join(env.get("ProgramFiles", ""), "TRAE SOLO CN"),
            os.path.join(env.get("LOCALAPPDATA", ""), "Programs", "TRAE SOLO CN"),
            "C:\\TRAE SOLO CN", "D:\\TRAE SOLO CN", "E:\\TRAE SOLO CN",
        ]
    for d in candidates:
        pj = os.path.join(d, "resources", "app", "product.json")
        try:
            with open(pj, "r", encoding="utf-8") as f:
                v = json.load(f).get("appVersion")
            if v:
                return str(v)
        except Exception:
            continue
    return IDE_VERSION


def _system_information():
    """尽力复刻客户端 getSystemInformation()：品牌/型号/CPU/系统版本。"""
    out = {"brand": "", "model": "", "cpu": "", "os_version": ""}
    try:
        import subprocess
        cmd = ("$ErrorActionPreference='SilentlyContinue';"
               "$cs=Get-CimInstance Win32_ComputerSystem;"
               "$cpu=Get-CimInstance Win32_Processor|Select-Object -First 1;"
               "$os=Get-CimInstance Win32_OperatingSystem;"
               "Write-Output ($cs.Manufacturer+'|'+$cs.Model+'|'+$cpu.Name+'|'+$os.Caption)")
        r = subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                           capture_output=True, timeout=25)
        parts = (r.stdout.decode("utf-8", "replace").strip().split("|") + [""] * 4)[:4]
        out.update({"brand": parts[0].strip(), "model": parts[1].strip(),
                    "cpu": " ".join(parts[2].split()), "os_version": parts[3].strip()})
        # Caption 形如 "Microsoft Windows 10 专业版"，客户端发送英文版（如 Windows 10 Pro）
        if out["os_version"].lower().startswith("microsoft "):
            out["os_version"] = out["os_version"][len("Microsoft "):]
        for zh, en in (("专业工作站版", "Pro for Workstations"), ("专业教育版", "Pro Education"),
                       ("家庭单语言版", "Home Single Language"), ("专业版", "Pro"),
                       ("家庭版", "Home"), ("企业版", "Enterprise"),
                       ("教育版", "Education"), ("物联网企业版", "IoT Enterprise")):
            if zh in out["os_version"]:
                out["os_version"] = out["os_version"].replace(zh, en)
                break
    except Exception:
        pass
    return out


def _exchange_token(session, raw_format=False):
    """调用 ExchangeToken 用 refreshToken 换新 token。

    返回 (result_dict 或 None, error_dict 或 None)。
    error_dict["kind"]: network / fatal / other。
    """
    kp = session.get("keypair") or {}
    if not session.get("refresh_token") or not kp.get("privateKeyPEM"):
        return None, {"kind": "fatal"}
    proof = sign_device_proof(kp["privateKeyPEM"], CLIENT_ID,
                              session["refresh_token"], raw_format=raw_format)
    # DeviceInfo 字段与客户端发送内容逐一对齐（服务端校验设备绑定，见日志实证）
    sysinfo = _system_information()
    ide_version = _ide_version()
    user = os.environ.get("USERNAME") or os.environ.get("USER") or "pc"
    device_info = {
        "DeviceID": session.get("device_key_id") or session.get("device_id") or "",
        "MachineID": session.get("machine_id") or "",
        "PlatformCode": "SOLO_PC",
        "DeviceType": "PC",
        "DeviceName": user + "的电脑",
        "DeviceModel": sysinfo["model"],
        "ClientVersion": ide_version,
        "DevicePublicKey": kp["publicKeyPEM"],
        "DeviceBrand": sysinfo["brand"],
        "DeviceCPU": sysinfo["cpu"],
        "OSInfo": "windows" if os.name == "nt" else "other",
        "OSVersion": sysinfo["os_version"],
    }
    payload = {
        "ClientID": CLIENT_ID,
        "ClientSecret": "",
        "RefreshToken": session["refresh_token"],
        "DeviceInfo": device_info,
        "DeviceProof": proof,
        "IDEVersion": ide_version,
    }
    headers = {"Content-Type": "application/json",
               "Accept": "application/json",
               "x-cloudide-token": session["token"]}
    endpoint = os.environ.get("TRAE_ENDPOINT") or DEFAULT_ENDPOINT
    code, body = post(endpoint + EXCHANGE_PATH, headers, payload, retry=False)

    if code in (CODE_NO_NETWORK, CODE_BUDGET_OUT):
        return None, {"kind": "network", "http": code}
    result = body.get("Result") if isinstance(body, dict) else None
    if 200 <= code < 300 and isinstance(result, dict) and result.get("Token"):
        return result, None
    err_code = ""
    if isinstance(body, dict):
        err_code = str((((body.get("ResponseMetadata") or {}).get("Error") or {})
                        .get("Code")) or "")
    kind = "fatal" if err_code in REFRESH_FATAL_CODES else "other"
    return None, {"kind": kind, "http": code, "code": err_code}


def _apply_new_token(session, auth_file, result):
    """把新 token 写回 storage.json：先备份，改键值，原子替换。"""
    now_ms = int(time.time() * 1000)
    old_exp = result.get("TokenExpireAt") or 0
    duration = result.get("TokenExpireDuration") or 0
    # 复刻客户端 bTe()：TokenExpireAt 已过且带 duration 时用 now+duration
    if old_exp and int(old_exp) < now_ms and duration:
        expired_at = _iso_ms(now_ms + int(duration))
    else:
        expired_at = _iso_ms(old_exp)
    refresh_exp = _iso_ms(result.get("RefreshExpireAt"))

    storage = load_storage(auth_file)
    try:
        info = json.loads(trae_decrypt(storage[AUTH_KEY_SUFFIX]).decode("utf-8"))
    except Exception:
        info = dict(session.get("info") or {})
    info.update({
        "token": result.get("Token") or info.get("token"),
        "refreshToken": result.get("RefreshToken") or info.get("refreshToken"),
        "expiredAt": expired_at,
        "refreshExpiredAt": refresh_exp or info.get("refreshExpiredAt"),
        "tokenReleaseAt": _iso_ms(now_ms),
    })
    storage[AUTH_KEY_SUFFIX] = trae_encrypt(
        json.dumps(info, ensure_ascii=False).encode("utf-8"))

    try:
        import shutil
        shutil.copy2(auth_file, auth_file + ".bak")
    except Exception:
        pass  # 备份失败不阻断写回（写回本身是原子替换）
    tmp = auth_file + ".tmp-trae-signin"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(storage, f, ensure_ascii=False)
    os.replace(tmp, auth_file)


def maybe_refresh(session, auth_file, forced=False):
    """token 自动续期入口。

    forced=True：token 已过期，续期是唯一出路（缺材料时直接报 TOKEN_EXPIRED）。
    forced=False：仅在临期（REFRESH_MARGIN_DAYS）且客户端未运行时尝试，
      失败不影响本次签到（当前 token 仍可用）。
    返回 (session, 事件 dict 或 None)。
    """
    if not forced:
        if os.environ.get("TRAE_FORCE_REFRESH") != "1" and not _token_expires_soon(session):
            return session, None
        if _client_running():
            # 客户端运行中会自行刷新，避免与其并发写凭据文件
            return session, None
    if not session.get("refresh_token") or not session.get("keypair"):
        if forced:
            raise AuthError("TOKEN_EXPIRED")
        return session, None

    result, err = _exchange_token(session)
    if result is None and err and err.get("kind") == "other":
        # 签名格式或参数被拒：换 IEEE-P1363 裸格式再试一次
        result, err = _exchange_token(session, raw_format=True)
    if result is None:
        if err and err.get("kind") == "fatal":
            # refreshToken 已失效，只能重新登录客户端
            raise AuthError("TOKEN_EXPIRED")
        if forced:
            raise AuthError("TOKEN_EXPIRED")
        detail = ""
        if err:
            detail = "HTTP %s%s" % (err.get("http", "?"),
                                    ("，业务码 %s" % err["code"]) if err.get("code") else "")
        return session, {"result": "REFRESH_FAILED",
                         "report": "token 自动续期未成功（%s），本次继续使用当前令牌"
                                   % (detail or "网络异常")}
    _apply_new_token(session, auth_file, result)
    new_session = load_session(auth_file)
    return new_session, {"result": "REFRESHED",
                         "report": "token 已自动续期，新有效期至 %s" % new_session.get("expired_at", "?")}


# ---------------------------------------------------------------------------
# HTTP（带时间预算与退避重试，结构参考 workbuddy-auto-signin）
# ---------------------------------------------------------------------------

def _start_budget():
    global _started_at
    _started_at = time.monotonic()


def _budget_left():
    if _started_at is None:
        return _budget_seconds
    return _budget_seconds - (time.monotonic() - _started_at)


def build_headers(session):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "Cloud-IDE-JWT %s" % session["token"],
        "User-Agent": "TRAE",
    }
    if session.get("device_id"):
        headers["x-device-id"] = session["device_id"]
    return headers


def _request(url, headers, payload=None, timeout=REQUEST_TIMEOUT):
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8")
            try:
                return resp.status, json.loads(raw)
            except Exception:
                return resp.status, {"raw": raw[:500]}
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw[:500]}
    except urllib.error.URLError as e:
        return CODE_NO_NETWORK, {"error": str(e.reason)}
    except Exception as e:
        return CODE_NO_NETWORK, {"error": str(e)}


def _retry_delays(code):
    if code == CODE_NO_NETWORK:
        return NETWORK_RETRY_DELAYS
    if code >= 500:
        return SERVER_RETRY_DELAYS
    return ()


def post(url, headers, payload=None, retry=True):
    """POST：默认带退避重试（签到接口幂等，重复提交无副作用）。"""
    if _budget_left() <= 1:
        return CODE_BUDGET_OUT, {"error": "已达本次运行时间预算，跳过剩余请求"}
    code, body = _request(url, headers, payload=payload,
                          timeout=max(1, min(REQUEST_TIMEOUT, _budget_left())))
    attempts = {}
    while retry:
        delays = _retry_delays(code)
        if not delays:
            break
        used = attempts.get(delays, 0)
        if used >= len(delays):
            break
        delay = delays[used]
        attempts[delays] = used + 1
        if _budget_left() <= delay + REQUEST_TIMEOUT:
            break
        time.sleep(delay)
        code, body = _request(url, headers, payload=payload,
                              timeout=max(1, min(REQUEST_TIMEOUT, _budget_left())))
    return code, body


# ---------------------------------------------------------------------------
# 输出
# ---------------------------------------------------------------------------

def _dumps(obj):
    try:
        return json.dumps(obj, ensure_ascii=False)
    except Exception:
        return str(obj)


def emit(out, action):
    """silent 模式写日志文件，其余模式打印 stdout；保证不抛异常、不打印令牌。"""
    if isinstance(out, dict):
        out = dict(out)
        out.setdefault("needs_attention", out.get("result") in (
            "ERROR", "UNKNOWN", "NETWORK", "TIMEOUT", "NO_AUTH", "NO_SESSION",
            "AUTH_ERROR", "AUTH_REJECTED"))
    payload = _dumps(out)
    if not str(action).startswith("silent"):
        try:
            print(payload)
            if not (isinstance(out, dict) and out.get("result") == "ERROR"):
                return
        except Exception:
            pass  # stdout 不可用时退到日志，至少不把结果丢掉
    line = "[%s] %s\n" % (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), payload)
    default_log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signin.log")
    for path in (os.environ.get("TRAE_SIGNIN_LOG") or default_log, default_log):
        try:
            with open(path, "a", encoding="utf-8") as lf:
                lf.write(line)
            return
        except Exception:
            continue


# ---------------------------------------------------------------------------
# 签到主逻辑
# ---------------------------------------------------------------------------

def _is_already_checked_in(body):
    if isinstance(body, dict):
        code = body.get("code")
        msg = str(body.get("message") or body.get("msg") or "")
        if code not in (0, None):
            return True
        if "已签" in msg or "already" in msg.lower():
            return True
    return False


def _auth_failure(code):
    if code == 401:
        return {"result": "AUTH_REJECTED",
                "report": "认证被拒绝（HTTP 401），请打开 TRAE SOLO CN 客户端重新登录",
                "needs_attention": True}
    return {"result": "FORBIDDEN",
            "report": "权限或业务拒绝（HTTP 403），请检查账号状态",
            "needs_attention": True}


def _already_report(status, via=None):
    credits = status.get("credits")
    extra = status.get("extra_credits")
    inner = []
    if credits is not None:
        inner.append("今日 +%s" % credits)
    if extra:
        inner.append("含连签奖励 +%s" % extra)
    prefix = via or "今日已签过"
    report = "%s（%s）" % (prefix, "，".join(inner)) if inner else prefix
    return {"result": "ALREADY", "report": report,
            "credits": credits, "extra_credits": extra}


def run_auto(headers, endpoint):
    """每日自动化主逻辑：查状态→未签才领→返回 (退出码, 汇报 dict)。"""
    base = endpoint + "/trae/api/v2/ug/checkin_credits"
    # req_source：1=IDE，2=SOLO/Lite（逆向自桌面端，服务端两者均接受）
    req_source = 2

    scode, sbody = post(base + "/status", headers, {"req_source": req_source})

    if scode == CODE_BUDGET_OUT:
        return 1, {"result": "TIMEOUT",
                   "report": "已达本次运行时间预算，签到跳过，下次自动重试"}
    if scode == CODE_NO_NETWORK:
        return 1, {"result": "NETWORK",
                   "report": "网络不可达，签到跳过，下次自动重试（%s）" % (sbody.get("error") or "")}
    if scode in (401, 403):
        return 1, _auth_failure(scode)
    if not (200 <= scode < 300):
        return 1, {"result": "ERROR",
                   "report": "签到状态接口返回异常（HTTP %s），请重新登录客户端或稍后重试" % scode,
                   "http": scode, "status_body": sbody}

    status = sbody if isinstance(sbody, dict) else {}
    if status.get("enable") is False:
        return 0, {"result": "INACTIVE", "report": "签到活动未开启", "enable": False}

    if status.get("checked_in") in (True, 1):
        return 0, _already_report(status)

    ccode, cbody = post(base + "/claim", headers, {"req_source": req_source})

    if ccode in (CODE_NO_NETWORK, CODE_BUDGET_OUT):
        return 1, {
            "result": "NETWORK" if ccode == CODE_NO_NETWORK else "TIMEOUT",
            "report": "领取请求未能送达，下次自动重试（%s）" % (
                (cbody.get("error") or "") if isinstance(cbody, dict) else "")}
    if ccode in (401, 403):
        return 1, _auth_failure(ccode)
    if _is_already_checked_in(cbody):
        # 幂等：服务端判定已领取，回查一次拿最新数值
        scode2, sbody2 = post(base + "/status", headers, {"req_source": req_source})
        fresh = sbody2 if (200 <= scode2 < 300 and isinstance(sbody2, dict)) else status
        return 0, _already_report(fresh, via="今日已签过（服务端判定已领取）")

    if isinstance(cbody, dict) and cbody.get("code") in (0, None) and 200 <= ccode < 300:
        # 领取成功后回查状态，拿积分数值
        scode2, sbody2 = post(base + "/status", headers, {"req_source": req_source})
        fresh = sbody2 if (200 <= scode2 < 300 and isinstance(sbody2, dict)) else {}
        credits = fresh.get("credits")
        extra = fresh.get("extra_credits")
        if credits is not None:
            report = "成功领取 %s 积分" % credits
            if extra:
                report += "（含连签奖励 +%s）" % extra
        else:
            report = "成功领取今日签到积分"
        return 0, {"result": "CLAIMED", "report": report,
                   "credits": credits, "extra_credits": extra}

    if isinstance(cbody, dict) and ("code" in cbody or "message" in cbody or "msg" in cbody):
        msg = cbody.get("message") or cbody.get("msg") or ("code %s" % cbody.get("code"))
        return 1, {"result": "ERROR",
                   "report": "领取失败：%s（HTTP %s）" % (msg, ccode),
                   "http": ccode, "claim_body": cbody}

    return 1, {"result": "UNKNOWN",
               "report": "未识别的领取返回，请检查接口：%s" % _dumps(cbody)[:200],
               "http": ccode, "claim_body": cbody}


def run_doctor(session):
    """离线自检：凭据可解、字段齐全、token 未过期。"""
    checks = []
    checks.append(("凭据文件可读且可解密", True))
    checks.append(("token 字段存在", bool(session.get("token"))))
    checks.append(("userId: %s" % (session.get("user_id") or "(空)"), True))
    checks.append(("deviceId: %s" % ((session.get("device_id") or "(未取到，不影响签到)")[:24]), True))
    checks.append(("token 过期时间: %s" % (session.get("expired_at") or "(未知)"), True))
    try:
        check_token_freshness(session)
        checks.append(("token 未过期", True))
    except AuthError as e:
        checks.append((str(e), False))
    checks.append(("refreshToken 有效期至: %s" % (session.get("refresh_expired_at") or "(未知)"),
                   bool(session.get("refresh_token"))))
    checks.append(("设备密钥对(自动续期): %s" % ("已找到" if session.get("keypair") else "未找到"),
                   bool(session.get("keypair"))))
    try:
        import cryptography  # noqa: F401
        checks.append(("AES 后端: cryptography", True))
    except ImportError:
        try:
            import Crypto  # noqa: F401
            checks.append(("AES 后端: pycryptodome", True))
        except ImportError:
            checks.append(("AES 后端: 纯 Python（慢但可用）", True))
    ok = all(flag for _, flag in checks)
    return {"result": "OK" if ok else "ATTENTION",
            "report": "自检完成：%s" % "；".join(name for name, _ in checks),
            "needs_attention": not ok}


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def _run(action):
    _start_budget()
    known = ("auto", "silent", "status", "claim", "doctor")
    if action not in known:
        emit({"result": "ERROR",
              "report": "未知命令：%s（可用：%s）" % (action, " / ".join(known))}, action)
        return 2

    auth_file, looked_in = find_auth_file()
    env_override = os.environ.get("TRAE_AUTH_FILE")
    if not auth_file or not os.path.exists(auth_file):
        if env_override:
            report = "TRAE_AUTH_FILE 指向的文件不存在：%s" % env_override
        else:
            report = ("未找到 TRAE 登录凭据。请先在本机登录 TRAE SOLO CN 桌面端；"
                      "或设置环境变量 TRAE_AUTH_FILE 指向 storage.json。")
        emit({"result": "NO_AUTH", "report": report, "looked_in": looked_in,
              "needs_attention": True}, action)
        return 2

    try:
        session = load_session(auth_file)
    except AuthError as e:
        emit(e.output(), action)
        return 2
    except json.JSONDecodeError as e:
        emit({"result": "ERROR",
              "report": "凭据文件不是合法 JSON（%s），请重新登录 TRAE SOLO CN 桌面端" % e}, action)
        return 2
    except Exception as e:
        emit({"result": "ERROR",
              "report": "读取登录凭据失败（%s: %s），请重新登录 TRAE SOLO CN 桌面端" % (type(e).__name__, e)},
             action)
        return 2

    if action == "doctor":
        emit(run_doctor(session), action)
        return 0

    # token 已过期 → 尝试用 refreshToken 续期救回；未过期但临期 → 机会式续期
    forced = False
    try:
        check_token_freshness(session)
    except AuthError:
        forced = True
    try:
        session, refresh_event = maybe_refresh(session, auth_file, forced=forced)
    except AuthError as e:
        emit(e.output(), action)
        return 2
    if refresh_event:
        emit(refresh_event, action)

    endpoint = os.environ.get("TRAE_ENDPOINT") or DEFAULT_ENDPOINT
    headers = build_headers(session)

    if action == "status":
        code, body = post(endpoint + "/trae/api/v2/ug/checkin_credits/status",
                          headers, {"req_source": 2})
        emit({"result": "OK" if 200 <= code < 300 else "ERROR",
              "http": code, "status": body}, action)
        return 0 if 200 <= code < 300 else 1

    # auto / silent / claim 共用同一条幂等路径
    code, out = run_auto(headers, endpoint)
    emit(out, action)
    return code


def main():
    action = sys.argv[1] if len(sys.argv) > 1 else "auto"
    try:
        return _run(action)
    except AuthError as e:
        emit(e.output(), action)
        return 1
    except Exception as e:
        # 无窗口运行下任何未捕获异常都会让当天的失败无痕消失，这里是最后防线
        emit({"result": "ERROR", "report": "脚本运行异常（%s: %s）" % (type(e).__name__, e),
              "needs_attention": True}, action)
        return 2


if __name__ == "__main__":
    sys.exit(main())
