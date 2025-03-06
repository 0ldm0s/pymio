# -*- coding: UTF-8 -*-
import copy
import time
import math
from decimal import Decimal
from datetime import datetime, timedelta, timezone
from dateutil.relativedelta import relativedelta, MO, SU
from typing import Tuple, Optional, Union


def timestamp2str(
        timestamp: int, iso_format: str = "%Y-%m-%d %H:%M:%S", hours: int = 0, minutes: int = 0,
        console_log=None
) -> Optional[str]:
    dt = None
    try:
        utc_time = datetime.fromtimestamp(timestamp)
        local_dt = utc_time + timedelta(hours=hours, minutes=minutes)
        dt = local_dt.strftime(iso_format)
    except Exception as e:
        if console_log:
            console_log.error(e)
    return dt


def str2timestamp(
        date: str, iso_format: str = "%Y-%m-%d %H:%M:%S", hours: int = 0, minutes: int = 0,
        console_log=None
) -> Optional[int]:
    ts = None
    try:
        time_array = time.strptime(date, iso_format)
        timestamp = time.mktime(time_array)
        local_time = datetime.fromtimestamp(timestamp)
        local_dt = local_time + timedelta(hours=hours, minutes=minutes)
        timestamp = time.mktime(local_dt.timetuple())
        ts = int(timestamp)
    except Exception as e:
        if console_log:
            console_log.error(e)
    return ts


def get_utc_now() -> int:
    dt = int(time.mktime(datetime.now(timezone.utc).timetuple()))
    return dt


def get_local_now(hours: int = 0, minutes: int = 0) -> int:
    utc_dt = datetime.now(timezone.utc).replace(tzinfo=timezone.utc)
    d = utc_dt.astimezone(timezone(timedelta(hours=hours, minutes=minutes)))
    dt = int(time.mktime(d.timetuple()))
    return dt


def get_this_week_range(timestamp: int, hours: int = 0, minutes: int = 0) -> Tuple[int, int]:
    try:
        utc_time = datetime.fromtimestamp(timestamp)
        local_dt = utc_time + timedelta(hours=hours, minutes=minutes)
        monday = local_dt + relativedelta(weekday=MO(-1), hour=0, minute=0, second=0)
        sunday = local_dt + relativedelta(weekday=SU, hour=0, minute=0, second=0)
        return int(time.mktime(monday.timetuple())), int(time.mktime(sunday.timetuple()))
    except Exception as e:
        str(e)
        return 0, 0


def get_this_month_range(timestamp: int, hours: int = 0, minutes: int = 0) -> Tuple[int, int]:
    try:
        local_date: Optional[str] = timestamp2str(timestamp, "%Y-%m", hours=hours, minutes=minutes)
        if local_date is None:
            return 0, 0
        start_year, start_month, *_ = local_date.split("-")
        return get_month_range(start_year=int(start_year), start_month=int(start_month), long=0)
    except Exception as e:
        str(e)
        return 0, 0


def get_month_range(start_year: int, start_month: int, long: int) -> Tuple[int, int]:
    from .validation_utils import is_number
    try:
        long = 1 if not is_number(long) else int(long)
        timestamp: int = str2timestamp(f"{start_year}-{start_month}-1", "%Y-%m-%d")
        utc_time = datetime.fromtimestamp(timestamp)
        if long >= 0:
            first_day = utc_time + relativedelta(day=1, hour=0, minute=0, second=0)
            last_day = utc_time + relativedelta(months=long, day=31, hour=0, minute=0, second=0)
        else:
            first_day = utc_time + relativedelta(months=long, day=1, hour=0, minute=0, second=0)
            last_day = utc_time + relativedelta(day=31, hour=0, minute=0, second=0)
        return int(time.mktime(first_day.timetuple())), int(time.mktime(last_day.timetuple()))
    except Exception as e:
        str(e)
        return 0, 0


def get_today(is_timestamp: bool = False, hours: int = 0, minutes: int = 0) -> Union[str, int]:
    dn: str = timestamp2str(get_utc_now(), "%Y-%m-%d", hours, minutes)
    if not is_timestamp:
        return dn
    timestamp: int = str2timestamp(dn, "%Y-%m-%d")
    return timestamp


def get_yesterday(is_timestamp: bool = False, hours: int = 0, minutes: int = 0) -> Union[str, int]:
    dt, _ = get_this_days_range(-1, hours, minutes)
    if not is_timestamp:
        return timestamp2str(dt, "%Y-%m-%d")
    return dt


def get_this_days_range(long: int, hours: int = 0, minutes: int = 0) -> Tuple[int, int]:
    from .validation_utils import is_number
    long = 1 if not is_number(long) else int(long)
    long = 1 if long == 0 else long
    # 获取当前日期
    dn: str = timestamp2str(get_utc_now(), "%Y-%m-%d", hours, minutes)
    start_time: int = str2timestamp(dn, "%Y-%m-%d", hours, minutes)
    end_time: int
    if long < 0:
        # 如果是往前推的天数
        end_time = copy.deepcopy(start_time)
        end_time = end_time
        start_time = start_time + (3600 * 24 * long)
    else:
        end_time = start_time + (3600 * 24 * long)
    return start_time, end_time


def get_now_microtime(max_ms_lan: int = 6, hours: int = 0, minutes: int = 0) -> int:
    mt: Decimal = Decimal(microtime(get_as_float=True, max_ms_lan=max_ms_lan, hours=hours, minutes=minutes))
    ms: Decimal = Decimal(str(int(math.pow(10, max_ms_lan))))
    return int(mt * ms)


def microtime(get_as_float=False, max_ms_lan: int = 6, hours: int = 0, minutes: int = 0) -> str:
    from .number_utils import rounded
    utc_dt = datetime.now(timezone.utc).replace(tzinfo=timezone.utc)
    d = utc_dt.astimezone(timezone(timedelta(hours=hours, minutes=minutes)))
    t = time.mktime(d.timetuple())
    ms: float = d.microsecond / 1000000.
    if get_as_float:
        ms_txt = str(ms)
        if len(ms_txt) >= max_ms_lan + 2:
            ms_txt = ms_txt[:max_ms_lan + 2]
        else:
            max_loop: int = (max_ms_lan - len(ms_txt)) + 2
            for i in range(max_loop):
                ms_txt = f"{ms_txt}0"
        a = rounded(Decimal(ms_txt), max_ms_lan)
        b = Decimal(t)
        dt = a + b
        return str(dt)
    else:
        return "%.8f %d" % (ms, t)
