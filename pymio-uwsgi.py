# -*- coding: UTF-8 -*-
import os
import sys
from typing import Union

root_path: str = os.path.abspath(os.path.dirname(__file__) + "/../")
sys.path.append(root_path)
# sys.path.insert(0, root_path)
from mio.sys import create_app, init_timezone, get_logger_level, init_uvloop

MIO_CONFIG: str = os.environ.get("MIO_CONFIG") or "default"
MIO_APP_CONFIG: str = os.environ.get("MIO_APP_CONFIG") or "config"
MIO_UVLOOP: Union[str, bool] = str(os.environ.get("MIO_UVLOOP", "0"))
MIO_UVLOOP = True if MIO_UVLOOP == "1" else False
if MIO_UVLOOP:
    init_uvloop()
init_timezone()
log_level, log_type, is_debug = get_logger_level(MIO_CONFIG)
application, *_ = create_app(
    MIO_CONFIG, root_path, MIO_APP_CONFIG, log_level=log_level, logger_type=log_type)
