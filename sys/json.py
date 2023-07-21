# -*- coding: UTF-8 -*-
import orjson
from flask.json.provider import JSONProvider
from typing import Union


class ORJSONDecoder:
    def __init__(self, **kwargs):
        # eventually take into consideration when deserializing
        self.options = kwargs

    @staticmethod
    def decode(obj):
        return orjson.loads(obj)


class ORJSONEncoder:
    def __init__(self, **kwargs):
        # eventually take into consideration when serializing
        self.options = kwargs

    @staticmethod
    def encode(obj):
        # decode back to str, as orjson returns bytes
        return orjson.dumps(obj).decode("utf-8")


class MioJsonProvider(JSONProvider):
    def dumps(self, obj, **kwargs):
        return orjson.dumps(obj)

    def loads(self, s: Union[bytes, bytearray, memoryview, str], **kwargs):
        return orjson.loads(s)
