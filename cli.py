# -*- coding: UTF-8 -*-
import os
import sys

root_path: str = os.path.abspath(os.path.dirname(__file__) + "/../")
sys.path.append(root_path)
from mio.sys import create_app, get_logger_level

MIO_CONFIG: str = os.environ.get("MIO_CONFIG") or "default"
MIO_APP_CONFIG: str = os.environ.get("MIO_APP_CONFIG") or "config"
log_level, log_type, is_debug = get_logger_level(MIO_CONFIG)

app, *_ = create_app(
    MIO_CONFIG, root_path, MIO_APP_CONFIG, is_cli=True, log_level=log_level, logger_type=log_type)
