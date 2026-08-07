"""RSA 加密/解密/签名/验签."""

from Crypto.PublicKey import RSA as _RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, SHA1, MD5
import base64

_HASH_MAP = {"SHA256": SHA256, "SHA1": SHA1, "MD5": MD5}


def rsa_encrypt(data: str, key_pem: str, padding: str = "OAEP") -> str:
    key = _RSA.import_key(key_pem)
    cipher = PKCS1_OAEP.new(key) if padding == "OAEP" else PKCS1_v1_5.new(key)
    return base64.b64encode(cipher.encrypt(data.encode("utf-8"))).decode("utf-8")


def rsa_decrypt(data: str, key_pem: str, padding: str = "OAEP") -> str:
    key = _RSA.import_key(key_pem)
    raw = base64.b64decode(data)
    if padding == "OAEP":
        return PKCS1_OAEP.new(key).decrypt(raw).decode("utf-8")
    sentinel = None
    result = PKCS1_v1_5.new(key).decrypt(raw, sentinel)
    if result is None:
        raise ValueError("RSA PKCS1v15 解密失败")
    return result.decode("utf-8")


def rsa_sign(data: str, private_key_pem: str, hash_algo: str = "SHA256") -> str:
    key = _RSA.import_key(private_key_pem)
    h = _HASH_MAP.get(hash_algo, SHA256).new(data.encode("utf-8"))
    return base64.b64encode(pkcs1_15.new(key).sign(h)).decode("utf-8")


def rsa_verify(data: str, signature_b64: str, public_key_pem: str, hash_algo: str = "SHA256") -> bool:
    try:
        key = _RSA.import_key(public_key_pem)
        h = _HASH_MAP.get(hash_algo, SHA256).new(data.encode("utf-8"))
        pkcs1_15.new(key).verify(h, base64.b64decode(signature_b64))
        return True
    except (ValueError, TypeError):
        return False
