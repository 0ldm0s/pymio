# -*- coding: UTF-8 -*-
import re
from typing import Any


def check_email(email: str) -> bool:
    re_str = r"^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){0,4}@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+){0,4}$"
    if re.match(re_str, email) is None:
        return False
    return True


def check_chinese_mobile(mobile: str) -> bool:
    try:
        return re.match(r"^1\d{10}$", mobile) is not None
    except Exception as e:
        str(e)
    return False


def is_number(s: Any) -> bool:
    if s is not None:
        try:
            s = str(s)
        except ValueError:
            return False
        try:
            float(s)
            return True
        except ValueError:
            pass

        try:
            import unicodedata
            unicodedata.numeric(s)
            return True
        except (TypeError, ValueError):
            pass

    return False


def get_bool(obj: Any) -> bool:
    """
    主要用于excel中，将代表true的字符转换为实际的布尔值
    """
    from .string_utils import str2int
    obj = False if obj is None else obj
    if isinstance(obj, bool) is False:
        if is_number(obj):
            obj = True if str2int(obj) == 1 else False
        elif isinstance(obj, str):
            tmp: str = str(obj).strip().lower()
            if tmp == "y" or tmp == "t" or tmp == "yes" or tmp == "true":
                obj = True
            else:
                obj = False
        else:
            obj = False
    return obj


def in_dict(dic: dict, key: str) -> bool:
    for kt in dic.keys():
        if kt == key:
            return True
    return False


def is_enable(dic: dict, key: str) -> bool:
    """
    主要用于判断权限字典内对应的键是否为布尔值。
    要求字典内对应的元素的字典必须为布尔值，否则返回false
    """
    if not in_dict(dic, key):
        return False
    _ = dic[key]
    if not isinstance(_, bool):
        return False
    return _
