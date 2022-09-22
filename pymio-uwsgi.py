# -*- coding: UTF-8 -*-
import os
import sys

root_path: str = os.path.abspath(os.path.dirname(__file__) + '/../')
sys.path.append(root_path)
from typing import Optional
from mio.sys import create_app, init_timezone, init_uvloop, get_cpu_limit, get_logger_level

MIO_CONFIG: str = os.environ.get('MIO_CONFIG') or 'default'
MIO_APP_CONFIG: str = os.environ.get('MIO_APP_CONFIG') or 'config'
MIO_LIMIT_CPU: int = get_cpu_limit()
pid_file_path: Optional[str] = os.environ.get('MIO_PID_FILE') or None
domain_socket: Optional[str] = os.environ.get('MIO_DOMAIN_SOCKET') or None
init_timezone()
init_uvloop()
log_level, log_type, is_debug = get_logger_level(MIO_CONFIG)
application, _, console_log = create_app(
    MIO_CONFIG, root_path, MIO_APP_CONFIG, log_level=log_level, logger_type=log_type)
