# -*- coding: UTF-8 -*-
import base64
import inspect
import binascii
from Crypto import Random
from Crypto.Cipher import DES3
from Crypto.Random import get_random_bytes
from typing import Optional
from mio.util.Helper import base64_decode
from .base import BaseModel


class Des3(BaseModel):
    def __init__(
            self, key: Optional[str] = None, iv: Optional[str] = None, aad: Optional[str] = None,
            is_hex: bool = False, **kwargs):
        id(aad), id(kwargs)
        super().__init__(self.__class__.__name__)
        console_log = self.__get_logger__(inspect.stack()[0].function)
        if key:
            try:
                if is_hex:
                    self._key = bytes.fromhex(key)
                else:
                    self._key = base64_decode(key)
            except Exception as e:
                console_log.error(e)
        if self._key is None:
            self._key = DES3.adjust_key_parity(get_random_bytes(24))
        if iv:
            try:
                if is_hex:
                    self._iv = bytes.fromhex(iv)
                else:
                    self._iv = base64_decode(iv)
            except Exception as e:
                console_log.error(e)
        if self._iv is None:
            self._iv = Random.new().read(DES3.block_size)

    def encrypt(self, msg: bytes) -> Optional[bytes]:
        console_log = self.__get_logger__(inspect.stack()[0].function)
        try:
            cipher_encrypt = DES3.new(self._key, DES3.MODE_OFB, self._iv)
            cipher: bytes = cipher_encrypt.encrypt(msg)
            return cipher
        except Exception as e:
            console_log.error(e)
            return None

    def decrypt(self, cipher: bytes) -> Optional[bytes]:
        console_log = self.__get_logger__(inspect.stack()[0].function)
        try:
            cipher_decrypt = DES3.new(self._key, DES3.MODE_OFB, self._iv)
            plain: bytes = cipher_decrypt.decrypt(cipher)
            return plain
        except Exception as e:
            console_log.error(e)
            return None

    def b64_encrypt(self, msg: str) -> Optional[str]:
        b64_msg: bytes = base64.b64encode(msg.encode("UTF-8"))
        cipher: Optional[bytes] = self.encrypt(b64_msg)
        if cipher is None:
            return None
        return str(binascii.b2a_hex(cipher), encoding="UTF-8")

    def b64_decrypt(self, cipher: str) -> Optional[str]:
        b64_cipher: bytes = binascii.a2b_hex(cipher)
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
