# -*- coding: UTF-8 -*-
import base64
import inspect
import binascii
from cryptography.hazmat.primitives.ciphers import algorithms
from typing import Optional
from mio.util.Helper import random_char
from mio.util.Logs import LogHandler
from . import Core


class ChaCha20(object):
    key: bytes
    iv: bytes

    def __get_logger__(self, name: str) -> LogHandler:
        name = f"{self.__class__.__name__}.{name}"
        return LogHandler(name)

    def __init__(self, key: Optional[str] = None, iv: Optional[str] = None):
        if key is None or len(key) != 32:
            self.key = random_char(32).encode("utf-8")
        else:
            self.key = key.encode("utf-8")
        if iv is None or len(iv) != 16:
            self.iv = random_char(16).encode("utf-8")
        else:
            self.iv = iv.encode("utf-8")

    def encrypt(self, msg: bytes) -> Optional[bytes]:
        console_log = self.__get_logger__(inspect.stack()[0].function)
        try:
            cipher: bytes = Core.go_encrypt(msg, algorithms.ChaCha20(self.key, self.iv), None)
            return cipher
        except Exception as e:
            console_log.error(e)
            return None

    def decrypt(self, cipher: bytes) -> Optional[bytes]:
        console_log = self.__get_logger__(inspect.stack()[0].function)
        try:
            plain: bytes = Core.go_decrypt(cipher, algorithms.ChaCha20(self.key, self.iv), None)
            return plain
        except Exception as e:
            console_log.error(e)
            return None

    def b64_encrypt(self, msg: str) -> Optional[str]:
        b64_msg: bytes = base64.b64encode(msg.encode("utf-8"))
        cipher: Optional[bytes] = self.encrypt(b64_msg)
        if cipher is None:
            return None
        return str(binascii.b2a_hex(cipher), encoding="utf-8")

    def b64_decrypt(self, cipher: str) -> Optional[str]:
        b64_cipher: bytes = binascii.a2b_hex(cipher)
        plain: Optional[bytes] = self.b64_decrypt(b64_cipher)
        if plain is None:
            return None
        b64_msg: bytes = base64.b64decode(plain)
        return str(b64_msg, encoding="utf-8")

    def get_key(self):
        return str(self.key, encoding="utf-8")

    def get_iv(self):
        return str(self.iv, encoding="utf-8")
