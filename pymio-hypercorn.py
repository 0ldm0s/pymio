# -*- coding: UTF-8 -*-
import os
import sys
from asgiref.wsgi import WsgiToAsgi

root_path: str = os.path.abspath(os.path.dirname(__file__) + "/../")
sys.path.append(root_path)
from mio.sys import create_app, init_timezone, get_logger_level

MIO_CONFIG: str = os.environ.get("MIO_CONFIG") or "default"
MIO_APP_CONFIG: str = os.environ.get("MIO_APP_CONFIG") or "config"
init_timezone()
log_level, log_type, is_debug = get_logger_level(MIO_CONFIG)
application, *_ = create_app(
    MIO_CONFIG, root_path, MIO_APP_CONFIG, log_level=log_level, logger_type=log_type)
asgi_app = WsgiToAsgi(application)
