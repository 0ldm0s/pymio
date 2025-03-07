#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import os
import sys
import asyncio
from flask import Flask
from typing import Optional, Union

root_path: str = os.path.abspath(os.path.dirname(__file__) + "/../")
sys.path.insert(0, root_path)
from mio.sys import create_app, init_timezone, init_uvloop, get_cpu_limit, \
    get_logger_level, get_buffer_size, os_name
from mio.util.Helper import write_txt_file, is_number, str2int
from mio.util.Logs import LogHandler
from config import MIO_HOST, MIO_PORT

MIO_CONFIG: str = os.environ.get("MIO_CONFIG") or "default"
MIO_APP_CONFIG: str = os.environ.get("MIO_APP_CONFIG") or "config"
MIO_LIMIT_CPU: int = get_cpu_limit()
pid_file_path: Optional[str] = os.environ.get("MIO_PID_FILE") or None
domain_socket: Optional[str] = os.environ.get("MIO_DOMAIN_SOCKET") or None
MIO_UVLOOP: Union[str, bool] = str(os.environ.get("MIO_UVLOOP", "0"))
MIO_UVLOOP = True if MIO_UVLOOP == "1" else False
init_timezone()
if MIO_UVLOOP:
    init_uvloop()
for arg in sys.argv:
    if not arg.startswith("--"):
        continue
    arg = arg[2:]
    temp = arg.split("=")
    if temp[0].lower() == "app_config":
        MIO_APP_CONFIG: str = temp[1]
        continue
    if temp[0].lower() == "host":
        MIO_HOST: str = temp[1]
        os.environ["MIO_HOST"] = MIO_HOST
        continue
    if temp[0].lower() == "port":
        try:
            port: int = int(temp[1])
            MIO_PORT = port
            os.environ["MIO_PORT"] = str(MIO_PORT)
        except Exception as e:
            print(e)
            exit()
        continue
    if temp[0].lower() == "config":
        MIO_CONFIG = temp[1]
        continue
    if temp[0].lower() == "pid":
        pid_file_path: str = temp[1]
        continue
    if temp[0].lower() == "cpu_limit":
        if os_name in ["windows", "unknown"]:
            # 不可在windows下设置cpu数
            continue
        MIO_LIMIT_CPU = 1 if not is_number(temp[1]) else str2int(temp[1])
        continue
    if temp[0].lower() == "ds":
        domain_socket = temp[1]
        continue
if pid_file_path is not None:
    write_txt_file(pid_file_path, str(os.getpid()))
log_level, log_type, is_debug = get_logger_level(MIO_CONFIG)
max_buffer_size, max_body_size = get_buffer_size()
app: Flask
console_log: LogHandler
app, console_log = create_app(
    MIO_CONFIG, root_path, MIO_APP_CONFIG, log_level=log_level, logger_type=log_type)

if __name__ == "__main__":
    try:
        try:
            from hypercorn.asyncio import serve
            from hypercorn.config import Config
            from quart import Quart
            from mio.sys.MountMiddleware import MountMiddleware

            # 初始化Quart应用
            quart_app = Quart(__name__)
            quart_app.asgi_app = MountMiddleware(quart_app.asgi_app, app)
            # 配置Hypercorn参数
            config = Config()
            config.bind = [f"unix:{domain_socket}"] if domain_socket else [f"{MIO_HOST}:{MIO_PORT}"]
            if MIO_UVLOOP:
                config.worker_class = "uvloop"
            config.workers = MIO_LIMIT_CPU if MIO_LIMIT_CPU > 1 else 1
            config.loglevel = "debug" if MIO_CONFIG != "production" else "warning"
            config.accesslog = "-"
            # config.access_log_format = '%h %r %s %b "%(Referer)i" "%(UserAgent)i"'
            config.access_log_format = (
                '%(h)s(%(X-Forwarded-For)s) %(r)s %(s)s %(b)s "%(f)s" "%(a)s"'  # 注意变量名规范
            )
            asyncio.run(serve(quart_app, config))
        except Exception as e:
            console_log.warning(f"无法启动Quart服务（{str(e)}），正在回退到纯Flask模式")
            # 使用更安全的Flask内置服务器配置
            app.run(
                host=MIO_HOST,
                port=int(MIO_PORT),
                use_reloader=False,
                use_debugger=False,
                threaded=True,
                passthrough_errors=True
            )
    except KeyboardInterrupt:
        console_log.warning("WebServer Shutdowning...")
    except Exception as e:
        console_log.error(f"Server Error: {str(e)}")
    finally:
        console_log.info("WebServer Closed.")
