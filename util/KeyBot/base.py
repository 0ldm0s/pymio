# -*- coding: UTF-8 -*-
import inspect
from typing import Optional
from mio.util.Logs import LogHandler
from mio.util.Helper import base64_encode, base64_decode


class BaseModel:
    VERSION: str = "0.3"
    _class_name: str
    _key: Optional[bytes] = None
    _iv: Optional[bytes] = None
    _aad: Optional[bytes] = None

    def __get_logger__(self, name: str) -> LogHandler:
        name = f"{self._class_name}.{name}"
        return LogHandler(name)

    def __init__(self, _class_name: str):
        self._class_name = _class_name

    def set_key(self, default_key: Optional[bytes], key: Optional[str] = None, is_hex: bool = False):
        """
        设置密钥(key)，这里就不做细节判断了

        :param default_key: 默认的密钥
        :param key: 传入的密钥字符串，如果不传或为空，则使用默认值
        :param is_hex: 是否为hex字符串
        """
        console_log = self.__get_logger__(inspect.stack()[0].function)
        if key and len(key) > 0:
            try:
                if is_hex:
                    self._key = bytes.fromhex(key)
                else:
                    self._key = base64_decode(key)
            except Exception as e:
                console_log.error(e)
        if self._key is None:
            self._key = default_key

    def set_iv(self, default_iv: Optional[bytes], iv: Optional[str] = None, is_hex: bool = False):
        """
        设置初始向量(initialization vector, IV)

        :param default_iv: 默认的IV，这里就不做细节判断了
        :param iv: 传入的IV字符串，如果不传或为空，则使用默认值
        :param is_hex: 是否为hex字符串
        """
        console_log = self.__get_logger__(inspect.stack()[0].function)
        if iv and len(iv) > 0:
            try:
                if is_hex:
                    self._iv = bytes.fromhex(iv)
                else:
                    self._iv = base64_decode(iv)
            except Exception as e:
                console_log.error(e)
        if self._iv is None:
            self._iv = default_iv

    def encrypt(self, msg: bytes) -> Optional[bytes]:
        pass

    def decrypt(self, cipher: bytes) -> Optional[bytes]:
        pass

    def b64_encrypt(self, msg: bytes) -> Optional[str]:
        enc: Optional[bytes] = self.encrypt(msg)
        if enc is None:
            return None
        b64_msg: bytes = base64_encode(enc)
        return b64_msg.decode("UTF-8", "ignore")

    def b64_decrypt(self, enc: str) -> Optional[str]:
        b64_cipher: bytes = base64_decode(enc)
        plain: Optional[bytes] = self.decrypt(b64_cipher)
        if plain is None:
            return None
        return plain.decode("UTF-8", "ignore")

    def hex_encrypt(self, msg: bytes) -> Optional[str]:
        cipher: Optional[bytes] = self.encrypt(msg)
        if cipher is None:
            return None
        return cipher.hex()

    def hex_decrypt(self, cipher: str) -> Optional[str]:
        console_log = self.__get_logger__(inspect.stack()[0].function)
        try:
            enc: bytes = bytes.fromhex(cipher)
        except Exception as e:
            console_log.error(e)
            return None
        plain: Optional[bytes] = self.decrypt(enc)
        if plain is None:
            return None
        return plain.decode("UTF-8", "ignore")

    @property
    def key(self) -> Optional[str]:
        if self._key is None:
            return None
        return base64_encode(self._key, is_bytes=False)

    @property
    def iv(self) -> Optional[str]:
        if self._iv is None:
            return None
        return base64_encode(self._iv, is_bytes=False)

    @property
    def aad(self) -> Optional[str]:
        if self._aad is None:
            return None
        return base64_encode(self._aad, is_bytes=False)

    @property
    def key_hex(self) -> Optional[str]:
        if self._key is None:
            return None
        return self._key.hex()

    @property
    def iv_hex(self) -> Optional[str]:
        if self._iv is None:
            return None
        return self._iv.hex()

    @property
    def aad_hex(self) -> Optional[str]:
        if self._aad is None:
            return None
        return self._aad.hex()
