# -*- coding: UTF-8 -*-
import re
import copy
import zlib
import base64
import hashlib
import binascii
from typing import Union, Optional, List

try:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve
    from cryptography.hazmat.primitives.asymmetric.utils import (
        decode_dss_signature,
        encode_dss_signature,
    )
except ImportError:
    EllipticCurve = None
    decode_dss_signature = None
    encode_dss_signature = None


def md5(txt: str) -> str:
    md = hashlib.md5()
    md.update(txt.encode("UTF-8"))
    return md.hexdigest()


def base64_encode(message: bytes, is_bytes: bool = True) -> Union[bytes, str]:
    crypto: bytes = base64.b64encode(message)
    if is_bytes:
        return crypto
    return crypto.decode("UTF-8")


def base64_decode(crypto: str, is_bytes: bool = True) -> Union[bytes, str]:
    missing_padding = 4 - len(crypto) % 4
    if missing_padding:
        crypto += "=" * missing_padding
    message: bytes = base64.b64decode(crypto)
    if is_bytes:
        return message
    return message.decode("UTF-8")


def base64_txt_encode(message: str) -> str:
    return str(base64_encode(message.encode("UTF-8"), is_bytes=False))


def base64_txt_decode(crypto: str) -> str:
    return str(base64_decode(crypto, is_bytes=False))


def crc_file(filename: str) -> str:
    prev = 0
    for eachLine in open(filename, "rb"):
        prev = zlib.crc32(eachLine, prev)
    return "%X" % (prev & 0xFFFFFFFF)


def easy_encrypted(
        text: str, is_decode=True, key: Optional[str] = None, expiry: int = 0, console_log=None
) -> Optional[str]:
    from .datetime_utils import get_utc_now, microtime
    try:
        if key is None or len(key) <= 0:
            from flask import current_app
            plan_key: str = current_app.config["SECRET_KEY"]
        else:
            plan_key = key
        key_c_length: int = 4
        key = md5(plan_key)
        key_a: str = md5(key[0:16])
        key_b: str = md5(key[16:32])
        key_c: str
        if key_c_length <= 0:
            key_c = ""
        else:
            if is_decode:
                key_c = text[0:key_c_length]
            else:
                key_c = md5(microtime())[-key_c_length:]
        crypt_key: str = key_a + "" + md5(key_a + "" + key_c)
        key_length: int = len(crypt_key)
        new_data: bytes
        if is_decode:
            new_data = base64_decode(text[key_c_length:])
        else:
            expiry = expiry + get_utc_now() if expiry > 0 else 0
            expiry_str: str = "%010d" % expiry
            plan_text: str = expiry_str + "" + md5(text + "" + key_b)[0:16] + "" + text
            new_data = plan_text.encode("latin-1")
        string_length: int = len(new_data)
        decode_result: str = ""
        encode_result: bytes = b""
        box: List[int] = list(range(0, 256))
        rnd_key: List[int] = []
        for i in range(256):
            start: int = i % key_length
            end: int = start + 1
            rnd_key.append(ord(crypt_key[start:end]))
        j: int = 0
        for i in range(256):
            j = (j + box[i] + rnd_key[i]) % 256
            _tmp_box_: int = copy.deepcopy(box[i])
            box[i] = copy.deepcopy(box[j])
            box[j] = copy.deepcopy(_tmp_box_)
        a: int = 0
        j = 0
        for i in range(string_length):
            a = (a + 1) % 256
            j = (j + box[a]) % 256
            _tmp_box_: int = copy.deepcopy(box[a])
            box[a] = copy.deepcopy(box[j])
            box[j] = copy.deepcopy(_tmp_box_)
            od1: int = new_data[i]
            od2: int = box[(box[a] + box[j]) % 256]
            co: int = (od1 ^ od2)
            if is_decode:
                decode_result = decode_result + chr(co)
            else:
                encode_result = encode_result + bytes(chr(co), encoding="latin-1")
        if is_decode:
            t1: int = int(decode_result[0:10])
            t2: str = decode_result[10:26]
            t3: str = md5(decode_result[26:] + key_b)[0:16]
            if (t1 == 0 or t1 - get_utc_now() > 0) and t2 == t3:
                return decode_result[26:]
        else:
            b64code: bytes = base64_encode(encode_result)
            result: str = b64code.decode("latin-1")
            result = result.replace("=", "")
            result = key_c + "" + result
            test_password: Optional[str] = easy_encrypted(
                result, key=plan_key, expiry=expiry, console_log=console_log)
            if test_password == text:
                return result
    except Exception as e:
        if console_log:
            console_log.error(e)
    return None


def is_pem_format(key: bytes) -> bool:
    _PEMS = {
        b"CERTIFICATE",
        b"TRUSTED CERTIFICATE",
        b"PRIVATE KEY",
        b"PUBLIC KEY",
        b"ENCRYPTED PRIVATE KEY",
        b"OPENSSH PRIVATE KEY",
        b"DSA PRIVATE KEY",
        b"RSA PRIVATE KEY",
        b"RSA PUBLIC KEY",
        b"EC PRIVATE KEY",
        b"DH PARAMETERS",
        b"NEW CERTIFICATE REQUEST",
        b"CERTIFICATE REQUEST",
        b"SSH2 PUBLIC KEY",
        b"SSH2 ENCRYPTED PRIVATE KEY",
        b"X509 CRL",
    }
    _PEM_RE = re.compile(
        b"----[- ]BEGIN ("
        + b"|".join(_PEMS)
        + b""")[- ]----\r?
.+?\r?
----[- ]END \\1[- ]----\r?\n?""",
        re.DOTALL,
    )
    return bool(_PEM_RE.search(key))


def is_ssh_key(key: bytes) -> bool:
    _SSH_KEY_FORMATS = [
        b"ssh-ed25519",
        b"ssh-rsa",
        b"ssh-dss",
        b"ecdsa-sha2-nistp256",
        b"ecdsa-sha2-nistp384",
        b"ecdsa-sha2-nistp521",
    ]
    _SSH_PUBKEY_RC = re.compile(rb"\A(\S+)[ \t]+(\S+)")
    _CERT_SUFFIX = b"-cert-v01@openssh.com"

    if any(string_value in key for string_value in _SSH_KEY_FORMATS):
        return True

    ssh_pubkey_match = _SSH_PUBKEY_RC.match(key)
    if ssh_pubkey_match:
        key_type = ssh_pubkey_match.group(1)
        if _CERT_SUFFIX == key_type[-len(_CERT_SUFFIX):]:
            return True

    return False


def base64url_encode(_input: bytes) -> bytes:
    return base64.urlsafe_b64encode(_input).replace(b"=", b"")


def base64url_decode(_input: Union[str, bytes]) -> bytes:
    if isinstance(_input, str):
        _input = _input.encode("ascii")

    rem = len(_input) % 4

    if rem > 0:
        _input += b"=" * (4 - rem)

    return base64.urlsafe_b64decode(_input)


def bytes_from_int(val: int) -> bytes:
    remaining = val
    byte_length = 0

    while remaining != 0:
        remaining >>= 8
        byte_length += 1

    return val.to_bytes(byte_length, "big", signed=False)


def to_base64url_uint(val: int) -> bytes:
    if val < 0:
        raise ValueError("Must be a positive integer")

    int_bytes = bytes_from_int(val)

    if len(int_bytes) == 0:
        int_bytes = b"\x00"

    return base64url_encode(int_bytes)


def from_base64url_uint(val: Union[str, bytes]) -> int:
    if isinstance(val, str):
        val = val.encode("ascii")

    data = base64url_decode(val)
    return int.from_bytes(data, byteorder="big")


def number_to_bytes(num: int, num_bytes: int) -> bytes:
    padded_hex = "%0*x" % (2 * num_bytes, num)
    return binascii.a2b_hex(padded_hex.encode("ascii"))


def bytes_to_number(_string: bytes) -> int:
    return int(binascii.b2a_hex(_string), 16)


def der_to_raw_signature(der_sig: bytes, curve: Optional[EllipticCurve]) -> bytes:
    if curve is None or decode_dss_signature is None:
        raise RuntimeError("cryptography module is required for elliptic curve operations")

    num_bits = curve.key_size
    num_bytes = (num_bits + 7) // 8

    r, s = decode_dss_signature(der_sig)

    return number_to_bytes(r, num_bytes) + number_to_bytes(s, num_bytes)


def raw_to_der_signature(raw_sig: bytes, curve: Optional[EllipticCurve]) -> bytes:
    if curve is None or encode_dss_signature is None:
        raise RuntimeError("cryptography module is required for elliptic curve operations")

    num_bits = curve.key_size
    num_bytes = (num_bits + 7) // 8

    if len(raw_sig) != 2 * num_bytes:
        raise ValueError("Invalid signature")

    r = bytes_to_number(raw_sig[:num_bytes])
    s = bytes_to_number(raw_sig[num_bytes:])

    return encode_dss_signature(r, s)
