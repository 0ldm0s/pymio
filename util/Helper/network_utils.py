# -*- coding: UTF-8 -*-
import sys
import platform
import ipaddress
import subprocess
from flask import request
from typing import Any, Optional, List


def get_real_ip(
        idx: int = 0, show_all: bool = False, ipv6only: bool = True, console_log=None
) -> str:
    real_ip: str = ""
    if "HTTP_CF_CONNECTING_IP" in request.environ:
        real_ip = request.environ["HTTP_CF_CONNECTING_IP"]
    elif "HTTP_X_CLIENT" in request.environ:
        real_ip = request.environ["HTTP_X_CLIENT"]
    elif "HTTP_FORWARDED" in request.environ:
        http_forwarded: str = str(request.environ["HTTP_FORWARDED"])
        xp = http_forwarded.split(";")
        for s in xp:
            if s.startswith("for="):
                _, real_ip, *_ = s.split("=")
                if check_is_ip(real_ip):
                    break
    if len(real_ip) > 0:
        return real_ip
    if "HTTP_X_REAL_IP" in request.environ:
        real_ip = request.environ["HTTP_X_REAL_IP"]
    elif "HTTP_X_FORWARDED_FOR" in request.environ:
        real_ip = request.environ["HTTP_X_FORWARDED_FOR"]
    else:
        real_ip = request.environ["REMOTE_ADDR"]
    if "," in real_ip and not show_all:
        try:
            _tmp_: List[str] = real_ip.split(",")
            real_ip = _tmp_[idx].strip()
        except Exception as e:
            if console_log:
                console_log.error(e)
    if not ipv6only:
        # for haproxy v4v6 mode
        real_ip = real_ip.replace("::ffff:", "") if real_ip.startswith("::ffff:") else real_ip
    return real_ip


def check_is_ip(ip_addr: str) -> bool:
    try:
        ipaddress.ip_address(ip_addr)
        return True
    except ValueError:
        return False


def check_ua(keys: List[str]) -> bool:
    user_agent: str = str(request.headers.get("User-Agent")).lower()
    for k in keys:
        if k.lower() in user_agent:
            return True
    return False


def check_bot() -> bool:
    return check_ua(["bot", "spider", "google"])


def check_ie() -> bool:
    return check_ua(["MSIE", "like gecko"])


def get_canonical_os_name() -> str:
    if sys.platform in ("win32", "cygwin"):
        return "windows"
    if sys.platform == "darwin":
        result = subprocess.run(["sysctl", "-a", "machdep.cpu.brand_string"], stdout=subprocess.PIPE)
        brand_string: str = result.stdout.decode("UTF-8").strip().lower()
        if "apple" in brand_string:
            return "mac_m1"
        return "mac"
    if sys.platform.startswith("linux"):
        info: str = platform.processor()
        if info == "aarch64":
            return "linux_aarch64"
        return "linux"
    if "bsd" in sys.platform:
        if "freebsd" in sys.platform:
            return "freebsd"
        return "bsd"
    return "unknown"


def get_variable_from_request(
        key_name: str, default: Optional[Any] = "", method: str = "check", force_str: bool = False
) -> Optional[Any]:
    from .validation_utils import is_number
    method = "check" if method is None or not isinstance(method, str) else str(method).strip().lower()
    if default is None and force_str:
        default = ""
    if method == "check":
        word = request.form.get(key_name, None)
        if word is None:
            word = request.args.get(key_name, None)
            if key_name in request.headers:
                word = request.headers[key_name]
        word = default if word is None else word
    elif method == "post":
        word = request.form.get(key_name, default)
    elif method == "get":
        word = request.args.get(key_name, default)
    elif method == "header":
        word = request.headers[key_name] if key_name in request.headers else default
    else:
        return default
    if word is None:
        return default
    if is_number(word):
        if force_str:
            return str(word).strip()
        return word
    return str(word).strip()


def process_bar(num, total):
    rate = float(num) / total
    ratenum = int(100 * rate)
    r = "\r[{}{}]{}%".format("*" * ratenum, " " * (100 - ratenum), ratenum)
    sys.stdout.write(r)
    if num >= total:
        sys.stdout.write("\r\n")
    sys.stdout.flush()
