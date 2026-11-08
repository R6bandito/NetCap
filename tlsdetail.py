"""TLS 明细解析模块（NetCap 用）

把 tshark 提取的 TLS 握手字段翻译成可读文本，方便学习协议细节。

注意：tshark 不同类型的字段输出进制不统一（有的给 0x1301，有的给十进制 43），
所以统一用 _num() 解析，两种都吃。
"""

HS_TYPES = {
    0: "Hello Request", 1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket",
    5: "End of Early Data", 8: "Encrypted Extensions", 11: "Certificate",
    12: "Server Key Exchange", 13: "Certificate Request", 14: "Server Hello Done",
    15: "Certificate Verify", 16: "Client Key Exchange", 20: "Finished",
    24: "Key Update", 254: "Message Hash",
}

EXT_NAMES = {
    0: "server_name (SNI)", 5: "status_request (OCSP)", 10: "supported_groups",
    11: "ec_point_formats", 13: "signature_algorithms", 16: "ALPN",
    18: "signed_certificate_timestamp", 21: "padding", 22: "encrypt_then_mac",
    23: "extended_master_secret", 27: "compress_certificate",
    28: "record_size_limit", 35: "session_ticket", 41: "pre_shared_key",
    42: "early_data", 43: "supported_versions", 44: "cookie",
    45: "psk_key_exchange_modes", 49: "post_handshake_auth",
    50: "signature_algorithms_cert", 51: "key_share",
    65281: "renegotiation_info", 65037: "encrypted_client_hello (ECH)",
    17613: "application_settings (ALPS, Chrome)",
}

CIPHERS = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0xC02B: "ECDHE_ECDSA_AES_128_GCM_SHA256", 0xC02F: "ECDHE_RSA_AES_128_GCM_SHA256",
    0xC02C: "ECDHE_ECDSA_AES_256_GCM_SHA384", 0xC030: "ECDHE_RSA_AES_256_GCM_SHA384",
    0xCCA9: "ECDHE_ECDSA_CHACHA20_POLY1305", 0xCCA8: "ECDHE_RSA_CHACHA20_POLY1305",
    0xC013: "ECDHE_RSA_AES_128_CBC_SHA", 0xC014: "ECDHE_RSA_AES_256_CBC_SHA",
    0x009C: "RSA_AES_128_GCM_SHA256", 0x009D: "RSA_AES_256_GCM_SHA384",
    0x002F: "RSA_AES_128_CBC_SHA", 0x0035: "RSA_AES_256_CBC_SHA",
    0x000A: "RSA_3DES_EDE_CBC_SHA", 0x0005: "RSA_RC4_128_SHA",
}

GROUPS = {
    0x001D: "x25519", 0x001E: "x448", 0x0017: "secp256r1 (P-256)",
    0x0018: "secp384r1 (P-384)", 0x0019: "secp521r1 (P-521)",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x11EC: "x25519mlkem768 (PQ)",
}

VERSIONS = {
    0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3",
}


def _num(v):
    """tshark 可能给 '0x1301' 也可能给 '43'"""
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s, 10)
    except Exception:
        return None


def is_grease(n):
    """GREASE 值形如 0x?a?a（两个字节相同且低半字节为 a）"""
    if n is None:
        return False
    return (n & 0xFF) == ((n >> 8) & 0xFF) and (n & 0x0F) == 0x0A


def _label(n, table, fallback_prefix):
    if n is None:
        return "?"
    if is_grease(n):
        return f"GREASE (0x{n:04x})"
    return table.get(n, f"{fallback_prefix} 0x{n:04x}")


def name_ext(t):
    return _label(_num(t), EXT_NAMES, "未知扩展")


def name_cipher(c):
    return _label(_num(c), CIPHERS, "套件")


def name_group(g):
    return _label(_num(g), GROUPS, "组")


def name_version(v):
    return _label(_num(v), VERSIONS, "版本")


def name_hs(t):
    n = _num(t)
    return HS_TYPES.get(n, f"类型 {t}") if n is not None else str(t)
