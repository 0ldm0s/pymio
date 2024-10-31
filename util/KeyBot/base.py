# -*- coding: UTF-8 -*-
from typing import Optional
from mio.util.Logs import LogHandler
from mio.util.Helper import base64_encode


class BaseModel(object):
    VERSION: str = "0.1"
    _class_name: str
    _key: Optional[bytes] = None
    _iv: Optional[bytes] = None
    _aad: Optional[bytes] = None

    def __get_logger__(self, name: str) -> LogHandler:
        name = f"{self._class_name}.{name}"
        return LogHandler(name)

    def __init__(self, _class_name: str):
        self._class_name = _class_name

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
