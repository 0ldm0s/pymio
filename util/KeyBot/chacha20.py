# -*- coding: UTF-8 -*-
import os
import struct
import base64
import inspect
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from typing import Optional
from mio.util.Helper import random_char, base64_decode, base64_encode
from .base import BaseModel


class ChaCha20(BaseModel):
    _is_poly1305: bool = True
    _counter: int = 0

    def __init__(
            self, key: Optional[str] = None, iv: Optional[str] = None, aad: Optional[str] = None,
            is_hex: bool = False, **kwargs):
        """
        初始化加密函数
        :param key: 加密密钥，两种方式传入，hex或base64，不填则自动生成
        :param iv: nonce，两种方式传入，hex或base64，不填则自动生成
        """
        super().__init__(self.__class__.__name__)
        console_log = self.__get_logger__(inspect.stack()[0].function)
        aad_len: int = 16
        if "is_poly1305" in kwargs:
            self._is_poly1305 = kwargs.get("is_poly1305")
        if "counter" in kwargs:
            self._counter = kwargs.get("counter")
        if "aad_len" in kwargs:
            aad_len = kwargs.get("aad_len")
        if key:
            try:
                if is_hex:
                    self._key = bytes.fromhex(key)
                else:
                    self._key = base64_decode(key)
            except Exception as e:
                console_log.error(e)
        if self._key is None:
            self._key = ChaCha20Poly1305.generate_key()
        if iv:
            try:
                if is_hex:
                    self._iv = bytes.fromhex(iv)
                else:
                    self._iv = base64_decode(iv)
            except Exception as e:
                console_log.error(e)
        if self._iv is None:
            if self._is_poly1305:
                self._iv = os.urandom(12)
            else:
                self._iv = os.urandom(8)
        if aad:
            if aad.lower().strip() == "none":
                self._aad = os.urandom(aad_len)
            else:
                try:
                    if is_hex:
                        self._aad = bytes.fromhex(aad)
                    else:
                        self._aad = base64_decode(aad)
                except Exception as e:
                    console_log.error(e)
                    raise e

    def encrypt(self, msg: bytes) -> Optional[bytes]:
        console_log = self.__get_logger__(inspect.stack()[0].function)
        try:
            cipher: bytes
            if self._is_poly1305:
                chacha = ChaCha20Poly1305(self._key)
                cipher = chacha.encrypt(self._iv, msg, self._aad)
            else:
                full_nonce = struct.pack("<Q", self._counter) + self._iv
                chacha = algorithms.ChaCha20(self._key, full_nonce)
                _cipher = Cipher(chacha, mode=None)
                encryptor = _cipher.encryptor()
                cipher = encryptor.update(msg)
            return cipher
        except Exception as e:
            console_log.error(e)
            return None

    def decrypt(self, cipher: bytes) -> Optional[bytes]:
        console_log = self.__get_logger__(inspect.stack()[0].function)
        try:
            plain: bytes
            if self._is_poly1305:
                chacha = ChaCha20Poly1305(self._key)
                plain = chacha.decrypt(self._iv, cipher, self._aad)
            else:
                full_nonce = struct.pack("<Q", self._counter) + self._iv
                chacha = algorithms.ChaCha20(self._key, full_nonce)
                _cipher = Cipher(chacha, mode=None)
                decryptor = _cipher.decryptor()
                plain = decryptor.update(cipher)
            return plain
        except InvalidTag:
            console_log.error("authentication tag doesn’t validate")
        except Exception as e:
            console_log.error(e)
        return None

    def b64_encrypt(self, msg: str) -> Optional[str]:
        b64_msg: bytes = base64.b64encode(msg.encode("UTF-8"))
        cipher: Optional[bytes] = self.encrypt(b64_msg)
        if cipher is None:
            return None
        return base64_encode(cipher, is_bytes=False)

    def b64_decrypt(self, cipher: str) -> Optional[str]:
        b64_cipher: bytes = base64_decode(cipher)
        plain: Optional[bytes] = self.decrypt(b64_cipher)
        if plain is None:
            return None
        b64_msg: bytes = base64.b64decode(plain)
        return str(b64_msg, encoding="UTF-8")

    def hex_encrypt(self, msg: str) -> Optional[str]:
        hex_msg: bytes = base64.b64encode(msg.encode("UTF-8"))
        cipher: Optional[bytes] = self.encrypt(hex_msg)
        if cipher is None:
            return None
        return cipher.hex()

    def hex_decrypt(self, cipher: str) -> Optional[str]:
        console_log = self.__get_logger__(inspect.stack()[0].function)
        try:
            hex_cipher: bytes = bytes.fromhex(cipher)
        except Exception as e:
            console_log.error(e)
            return None
        plain: Optional[bytes] = self.decrypt(hex_cipher)
        if plain is None:
            return None
        hex_msg: bytes = base64.b64decode(plain)
        return str(hex_msg, encoding="UTF-8")
