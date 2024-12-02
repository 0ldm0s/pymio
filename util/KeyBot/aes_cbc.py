# -*- coding: UTF-8 -*-
import inspect
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from typing import Optional
from mio.util.Helper import random_char
from .base import BaseModel


class AesCBC(BaseModel):
    def __init__(
            self, key: Optional[str] = None, iv: Optional[str] = None, aad: Optional[str] = None,
            is_hex: bool = False, **kwargs):
        """
        初始化加密函数
        :param key: 加密密钥，两种方式传入，hex或base64，不填则自动生成
        :param iv: nonce，两种方式传入，hex或base64，不填则自动生成
        """
        id(aad), id(kwargs)
        super().__init__(self.__class__.__name__)
        default_key: Optional[bytes] = None
        default_iv: Optional[bytes] = None
        if key is None or len(key) == 0:
            default_key = random_char(size=16).encode("UTF-8")
        if iv is None or len(iv) == 0:
            default_iv = random_char(size=16).encode("UTF-8")
        self.set_key(default_key, key=key, is_hex=is_hex)
        self.set_iv(default_iv, iv=iv, is_hex=is_hex)

    def encrypt(self, msg: bytes) -> Optional[bytes]:
        console_log = self.__get_logger__(inspect.stack()[0].function)
        try:
            data = pad(msg, 16)
            cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
            enc: bytes = cipher.encrypt(data)
            return enc
        except Exception as e:
            console_log.error(e)
            return None

    def decrypt(self, enc: bytes) -> Optional[bytes]:
        console_log = self.__get_logger__(inspect.stack()[0].function)
        try:
            cipher = AES.new(self._key, AES.MODE_CBC, self._iv)
            plain: bytes = unpad(cipher.decrypt(enc), 16)
            return plain
        except Exception as e:
            console_log.error(e)
            return None
