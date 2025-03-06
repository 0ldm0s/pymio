# -*- coding: UTF-8 -*-
import random
import string
from decimal import Decimal
from typing import Any


def do_sum(*args) -> Decimal:
    """
    对传入的数字进行求和计算

    :param args: 传入计算用的变量，支持str,float,int。非数字则跳过
    """
    from .validation_utils import is_number
    calc_num: Decimal = Decimal("0")
    for num in args:
        if not is_number(num):
            continue
        calc_num += Decimal(str(num))
    return calc_num


def random_number(random_length: int = 8) -> int:
    """
    生成随机数字。注意：是数字而非字符串，因此第一个数字不会为0

    :param random_length: 生成长度
    :return: 生成的数字
    """
    if random_length < 1:
        random_length = 1
    chars = string.digits
    if random_length == 1:
        return int(random.choice(chars))
    while True:
        first_num = random.choice(chars)
        if first_num != "0":
            break
    num_word = "{}{}".format(
        first_num, "".join(random.choice(chars) for _ in range(random_length - 1)))
    return int(num_word)


def rounded(numerical: Any, decimal: int = 2) -> Decimal:
    from .validation_utils import is_number
    decimal = 0 if not is_number(decimal) or decimal <= 0 else decimal
    decimal_place: Decimal
    if not is_number(numerical):
        return Decimal("0")
    numerical_str: str = str(numerical)
    if decimal <= 0:
        decimal_place = Decimal(numerical_str).quantize(Decimal("1"), rounding="ROUND_HALF_UP")
    else:
        zero: str = "0" * (decimal - 1)
        decimal_place = Decimal(numerical_str).quantize(Decimal(f"0.{zero}1"), rounding="ROUND_HALF_UP")
    return decimal_place
