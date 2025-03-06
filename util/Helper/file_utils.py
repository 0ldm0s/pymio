# -*- coding: UTF-8 -*-
import os
import re
import time
from typing import Tuple, Union, Optional, List


def get_root_path() -> str:
    """
    获取当前项目的根路径
    """
    root_path = os.path.abspath(os.path.dirname(__file__) + "/../../../")
    return root_path


def file_lock(filename: str, txt: str = " ", exp: int = None, reader: bool = False) -> Tuple[int, str]:
    from .validation_utils import is_number
    lock = os.path.join(get_root_path(), "lock")
    if not os.path.exists(lock):
        os.makedirs(lock)
    lock = os.path.join(lock, filename)
    if not os.path.isfile(lock):
        is_ok, txt = write_txt_file(lock, txt)
        return -1 if not is_ok else 1, txt
    # 如果文件存在，则判断是否需要检测过期
    if exp is None or not is_number(exp):
        return 0, u"Locked." if not reader else read_txt_file(lock)
    exp = int(exp)
    if exp <= 0:
        return 0, u"Locked." if not reader else read_txt_file(lock)
    exp = int(exp * 60)  # 是否有超过界限的问题？
    file_time = int(os.stat(lock).st_mtime)
    if exp >= (int(time.time()) - file_time):
        os.unlink(lock)
        return file_lock(filename, txt, exp)
    # 判断是否要读取内容
    return 0, u"Locked." if not reader else read_txt_file(lock)


def read_txt_file(filename: str, encoding: str = "UTF-8", console_log=None) -> str:
    if not os.path.isfile(filename):
        return ""
    txt: str = ""
    try:
        with open(filename, "r", encoding=encoding, errors="ignore") as reader:
            for line in reader:
                if line is None or len(line) <= 0:
                    continue
                txt += line
        return txt
    except FileNotFoundError:
        if console_log:
            console_log.error("File not found.")
        return ""
    except UnicodeDecodeError as e:
        if console_log:
            console_log.error(f"Decode error in {filename}: {e}")
        return ""


def write_txt_file(filename: str, txt: str = " ", encoding: str = "UTF-8") -> Tuple[bool, str]:
    if os.path.isfile(filename):
        os.unlink(filename)
    try:
        with open(filename, "w", encoding=encoding) as locker:
            locker.write(txt)
        return True, "OK"
    except FileNotFoundError:
        return False, "File not found."
    except UnicodeDecodeError as e:
        return False, f"Decode error in {filename}: {e}"


def read_file(filename: str, method: str = "r", encoding: str = "UTF-8") -> Optional[Union[str, bytes]]:
    if not os.path.isfile(filename):
        return None
    with open(filename, method, encoding=encoding) as reader:
        txt = reader.read()
    return txt


def write_file(
        filename: str, txt: Union[str, bytes] = " ", method: str = "w+", encoding: str = "UTF-8"
) -> Tuple[bool, str]:
    try:
        with open(filename, method, encoding=encoding) as locker:
            locker.write(txt)
        return True, "OK"
    except Exception as e:
        return False, str(e)


def file_unlock(filename: str) -> Tuple[int, str]:
    lock: str = os.path.join(get_root_path(), "lock")
    if not os.path.exists(lock):
        return 1, u"Unlocked."
    try:
        lock = os.path.join(lock, filename)
        if os.path.isfile(lock):
            os.unlink(lock)
        return 1, u"Unlocked."
    except Exception as e:
        return -1, str(e)


def get_file_list(
        root_path: str, files: Optional[List[str]] = None, is_sub: bool = False, is_full_path: bool = True,
        include_hide_file: bool = False
) -> List[str]:
    files = files or []
    if not isinstance(files, list):
        return files if isinstance(files, list) else []
    for lists in os.listdir(root_path):
        if lists.startswith(".") or lists.endswith(".pyc"):
            if not include_hide_file:
                continue
        if is_full_path:
            path = os.path.join(root_path, lists)
        else:
            path = lists
        if is_sub and os.path.isdir(os.path.join(root_path, lists)):
            files = get_file_list(
                root_path=os.path.join(root_path, lists), files=files, is_sub=is_sub, is_full_path=is_full_path)
        else:
            files.append(path)
    return files


def check_file_in_list(file: str, file_list: List[str] = None) -> bool:
    if file is None or not isinstance(file, str) or \
            file_list is None or not isinstance(file_list, list):
        return False
    file = file.lower()
    if file in file_list:
        return True
    for f in file_list:
        if file.startswith(f.lower()):
            return True
    return False


def ant_path_matcher(ant_path: str, expected_path: str) -> bool:
    star = r"[^\/]+"
    double_star = r".*"
    slash = r"\/"
    question_mark = r"\w"
    dot = r"\."

    output = ant_path.replace(r"/", slash).replace(r".", dot)
    output = re.sub(r"(?<!\*)\*(?!\*)", star, output)
    output = output.replace(r"**", double_star)
    output = output.replace(r"?", question_mark)
    rc = re.compile(output, re.IGNORECASE)
    if rc.match(expected_path) is None:
        return False
    return True


def chear_list(waiting: List, check_type: type = str) -> List:
    checked: List = []
    if waiting is None or not isinstance(waiting, list):
        return checked
    for _item_ in waiting:
        if _item_ is None or not isinstance(_item_, check_type):
            continue
        if check_type == str:
            _item_ = str(_item_).strip()
            if len(_item_) == 0:
                continue
        checked.append(_item_)
    return checked
