# -*- coding: UTF-8 -*-
import re
import bleach
import random
import string
from decimal import Decimal
from bleach.css_sanitizer import CSSSanitizer
from typing import Any, Tuple, Union, Optional, Dict, TypeVar

T = TypeVar("T")


def str2int(text: str, default: Optional[int] = 0) -> Optional[int]:
    from .validation_utils import is_number
    if not is_number(text):
        return default
    return int(Decimal(text))


def get_keyword(
        keyword: str, default: Any, **kwargs: Dict[str, Any]
) -> Tuple[T, Dict[str, Any]]:
    """
    对传入的kwargs弹出指定keyword的数据。
    请注意：pop之后的数据会从kwargs里移除

    :param keyword: 从 kwargs 获取数据用的键
    :param default: 当获取不到数据时返回的默认值
    :param kwargs: 变量集
    :return: 弹出的数据和 kwargs
    """
    try:
        value = kwargs.pop(keyword)
    except KeyError:
        value = default
    return value, kwargs


def random_str(random_length: int = 8, letters: int = 0) -> str:
    """
    生成随机英文字符串(a-z和A-Z)

    :param random_length: 生成长度
    :param letters: 0允许同时大小写 1仅小写 2仅大写
    :return: 生成的字符串
    """
    if random_length < 1:
        random_length = 1
    chars = string.ascii_letters
    if letters == 1:
        chars = string.ascii_lowercase
    elif letters == 2:
        chars = string.ascii_uppercase
    return "".join(random.choice(chars) for _ in range(random_length))


def random_number_str(random_length: int = 8) -> str:
    """
    生成随机数字字符串。注意：是字符串而非数字

    :param random_length: 生成长度
    :return: 生成的字符串
    """
    if random_length < 1:
        random_length = 1
    chars = string.digits
    return "".join(random.choice(chars) for _ in range(random_length))


def random_char(size: int = 6, special: bool = False, letters: int = 0) -> str:
    """
    生成随机字符串(a-z和A-Z，数字和特殊字符)

    :param size: 生成长度
    :param special: 是否允许特殊字符
    :param letters: 0允许同时大小写 1仅小写 2仅大写
    :return: 生成的字符串
    """
    if size < 0:
        size = 1
    chars = string.ascii_letters
    if letters == 1:
        chars = string.ascii_lowercase
    elif letters == 2:
        chars = string.ascii_uppercase
    chars += string.digits
    if special:
        chars += "!@#$%^&*"
    return "".join(random.choice(chars) for _ in range(size))


def __eat_html__(html: str) -> str:
    dr = re.compile(r"<[^>]+>", re.S)
    dd = dr.sub("", html)
    return dd


def eat_html(html: str) -> str:
    """
    移除所有的html代码。

    仅用于提供旧版eat_html兼容性，将于2.1.0版之后废弃
    Args:
        html: 等待过滤的代码
    Returns:
        str: 过滤好的代码
    """
    return safe_html_code(html)


def safe_html_code(
        string_html: Optional[str] = "", is_all: bool = True, strip=True, strip_comments=True) -> str:
    """
    安全过滤富文本HTML内容，防御XSS攻击

    Args:
        string_html: 等待清理的文本
        is_all: 启用后等价于eat_html
        strip: 直接剥离非法标签（而非转义），若为False，则非法标签会被转义
        strip_comments: 是否清理注释

    Returns:
        str: 经过安全过滤的HTML字符串
    """
    if string_html is None:
        return ""
    string_html = string_html if isinstance(string_html, str) else str(string_html)
    if is_all:
        return __eat_html__(string_html)
    # 定义允许的HTML标签白名单
    allowed_tags = [
        "a", "b", "i", "u", "em", "strong", "p", "br",
        "ul", "ol", "li", "h1", "h2", "h3", "h4", "h5", "h6",
        "img", "div", "span", "table", "thead", "tbody", "tr", "td", "th",
        "pre", "code"
    ]
    # 定义允许的标签属性白名单
    allowed_attributes = {
        "*": ["style", "class", "title"],
        "a": ["href", "rel", "target"],
        "img": ["src", "alt", "width", "height"],
        "tr": ["rowspan", "colspan"],
        "td": ["rowspan", "colspan", "align"],
        "code": ["class"]
    }
    # 允许的URL协议白名单
    allowed_protocols = ["http", "https", "mailto", "data"]
    # CSS属性白名单（如果允许style属性）
    css_sanitizer = CSSSanitizer(allowed_css_properties=[
        "color", "font-weight", "text-align", "width", "height", "background-color"
    ])
    # 执行过滤清理
    clean_html = bleach.clean(
        text=string_html,
        tags=allowed_tags,
        attributes=allowed_attributes,
        protocols=allowed_protocols,
        css_sanitizer=css_sanitizer,
        strip=strip,  # 新参数：直接剥离非法标签（而非转义）
        strip_comments=strip_comments  # 移除注释
    )
    return clean_html


def get_args_from_dict(
        dt: Dict, ky: str, default: Optional[Any] = "", force_str: bool = False, check_type: bool = True,
) -> Optional[Any]:
    from .validation_utils import is_number
    if default is None and force_str:
        default = ""
    word = default if ky not in dt else dt[ky]
    if is_number(word):
        if force_str:
            return str(word).strip()
        return word
    if isinstance(word, str):
        return str(word).strip()
    if force_str:
        return ""
    if word is None:
        return default
    # ! 判断是否跟默认值一致
    if default and check_type and not type(word) is type(default):
        return default  # 避免出现需要list但实际给了str的情况
    return word


def force_bytes(value: Union[str, bytes]) -> bytes:
    if isinstance(value, str):
        return value.encode("UTF-8")
    elif isinstance(value, bytes):
        return value
    else:
        raise TypeError("Expected a string value")
