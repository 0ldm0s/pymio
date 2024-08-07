# -*- coding: utf-8 -*-
import os
import sys
import rtoml as tomllib
import time
import codecs
import logging
import asyncio
from celery import Celery
from flask import Flask, blueprints
from flask_cors import CORS
from flask_babel import Babel
from flask_bcrypt import Bcrypt
from flask_caching import Cache
from flask_redis import FlaskRedis
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
from tornado.ioloop import IOLoop
from typing import Tuple, Optional, List, Union
from mio.util.Helper import in_dict, is_enable, is_number, get_canonical_os_name
from mio.util.Logs import LogHandler, LoggerType, nameToLevel
from mio.sys.json import MioJsonProvider
from mio.sys.flask_mongoengine import MongoEngine

MIO_SYSTEM_VERSION = "1.8.4"
mail = None
crypt: Bcrypt = Bcrypt()
db: Optional[MongoEngine] = None
rdb: Optional[SQLAlchemy] = None
redis_db: Optional[FlaskRedis] = None
csrf: Optional[CSRFProtect] = None
cache: Optional[Cache] = None
babel: Optional[Babel] = None
celery_app: Optional[Celery] = None
socketio: Optional[SocketIO] = None
os_name: str = get_canonical_os_name()


def create_app(
        config_name: str, root_path: Optional[str] = None, config_clz: Optional[str] = None,
        logger_type: LoggerType = LoggerType, log_level: int = logging.DEBUG
) -> Tuple[Flask, List[tuple], LogHandler]:
    global cache, babel, csrf, redis_db, db, rdb, mail, celery_app, socketio
    console = LogHandler("PyMio", logger_type=logger_type, log_level=log_level)
    console.info(f"Initializing the system......profile: {config_name}")
    console.info(f"Pymio Version: {MIO_SYSTEM_VERSION}")
    config_clz: str = "config" if not isinstance(config_clz, str) else config_clz.strip()
    config_path: str = os.path.join(root_path, config_clz.replace(".", "/"))
    clazz = __import__(config_clz, globals(), fromlist=["config"])
    config: dict = getattr(clazz, "config")
    toml_file: str = os.path.join(config_path, "config.toml")
    if not os.path.isfile(toml_file):
        console.error(u"config.toml not found!")
        sys.exit(0)
    config_toml: dict = tomllib.load(
        codecs.open(toml_file, "r", "utf-8").read())
    if not in_dict(config_toml, "config"):
        console.error(u"config.toml format error!")
        sys.exit(0)
    base_config: dict = config_toml["config"]
    static_folder: str = "{root_path}/web/static" \
        if not in_dict(base_config, "static_folder") \
        else base_config["static_folder"]
    static_folder = static_folder.replace("{root_path}", root_path)
    static_folder = os.path.abspath(static_folder)
    if not os.path.isdir(static_folder):
        console.error(u"Static file path not found!")
        sys.exit(0)
    template_folder: str = "{root_path}/web/template"\
        if not in_dict(base_config, "template_folder") \
        else base_config["template_folder"]
    template_folder = template_folder.replace("{root_path}", root_path)
    template_folder = os.path.abspath(template_folder)
    if not os.path.isdir(template_folder):
        console.error(u"Template path not found!")
        sys.exit(0)
    config_name: str = "default" if not isinstance(config_name, str) else config_name
    config_name = config_name.lower()
    if not in_dict(config, config_name):
        console.error(u"Config invalid!")
        sys.exit(0)
    app: Flask = Flask(
        __name__, static_folder=static_folder, template_folder=template_folder)
    app.json_provider_class = MioJsonProvider
    app.json = MioJsonProvider(app)
    app.config.from_object(config[config_name])
    app.config["ENV"] = config_name
    config[config_name].init_app(app)
    babel = Babel(app)
    if in_dict(base_config, "csrf"):
        if is_enable(base_config["csrf"], "enable"):
            csrf = CSRFProtect()
            csrf.init_app(app)
    if is_enable(app.config, "MIO_SOCKETIO"):
        socketio = SocketIO(app, cors_allowed_origins='*')
    if is_enable(app.config, "MIO_MAIL"):
        from flask_mail import Mail
        mail = Mail()
        mail.init_app(app)
    if is_enable(app.config, "MONGODB_ENABLE"):
        db = MongoEngine()
        db.init_app(app)
        # ! 至少输出警告级别
        logging.getLogger('pymongo').setLevel(logging.WARN)
    if is_enable(app.config, "RDBMS_ENABLE"):
        rdb = SQLAlchemy()
        rdb.init_app(app)
    if is_enable(app.config, "CELERY_ENABLE"):
        celery_app = Celery(
            app.import_name,
            broker=app.config["CELERY_BROKER_URL"],
            backend=app.config["CELERY_BACKEND_URL"]
        )
        logging.getLogger('amqp').setLevel(log_level)
        logging.getLogger('celery').setLevel(log_level)
    if is_enable(app.config, "REDIS_ENABLE"):
        redis_db = FlaskRedis()
        redis_db.init_app(app)
    if is_enable(app.config, "CORS_ENABLE"):
        if not in_dict(app.config, "CORS_URI"):
            console.error(u"CORS_URI not define.")
            sys.exit(0)
        CORS(app, resources=app.config["CORS_URI"])
    if is_enable(app.config, "CACHED_ENABLE"):
        cache = Cache(app)
    blueprints_config: List[dict] = config_toml["blueprint"] if in_dict(
        config_toml, "blueprint") else []
    for blueprint in blueprints_config:
        key: str = list(blueprint.keys())[0]
        clazz = __import__(blueprint[key]["class"], globals(), fromlist=[key])
        bp: blueprints.Blueprint = getattr(clazz, key)
        if in_dict(blueprint[key], "url_prefix"):
            app.register_blueprint(bp, url_prefix=blueprint[key]["url_prefix"])
        else:
            app.register_blueprint(bp)
    wss: List[tuple] = []
    # ! 这里适配tornado的websocket，如果使用flask的websock，则不需要定义
    # ! 如果使用uwsgi，则需要使用对应的引擎，用错引擎会直接报错
    websocket_config: List[dict] = config_toml["websocket"] \
        if in_dict(config_toml, "websocket") else []
    for websocket in websocket_config:
        key: str = list(websocket.keys())[0]
        clazz = __import__(websocket[key]["class"], globals(), fromlist=[key])
        ws = getattr(clazz, key)
        if not in_dict(websocket[key], "path"):
            console.error("Path must be set in config.toml.")
            sys.exit(0)
        wss.append((websocket[key]["path"], ws))
    return app, wss, console


def get_timezone_config() -> str:
    try:
        from config import Config
        tz: str = getattr(Config, "MIO_TIMEZONE")
        return tz
    except Exception as e:
        str(e)
        return "Asia/Shanghai"


def init_timezone():
    try:
        tz: str = get_timezone_config()
        os.environ["TZ"] = tz
        time.tzset()
    except Exception as e:
        str(e)


def init_uvloop():
    try:
        if os_name == "unknown":
            IOLoop.configure("tornado.platform.asyncio.AsyncIOLoop")
            return
        if os_name == "windows":
            import winloop
            asyncio.set_event_loop_policy(winloop.EventLoopPolicy())
            winloop.install()
            return
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except Exception as e:
        str(e)
        IOLoop.configure("tornado.platform.asyncio.AsyncIOLoop")


def get_event_loop():
    return asyncio.get_event_loop()


def get_logger_level(config_name: str) -> Tuple[int, LoggerType, bool]:
    config_name = config_name.replace("\"", "").replace("\"", "").lower()
    is_debug = False if config_name == "production" else True
    mio_logger_level: str = os.environ.get("MIO_LOGGER_LEVEL") or ""
    mio_logger_type: str = os.environ.get("MIO_LOGGER_TYPE") or ""
    log_level: Union[str, int] = logging.getLevelName(mio_logger_level)
    log_type: Optional[LoggerType] = nameToLevel.get(mio_logger_type)
    if not is_number(log_level):
        log_level = logging.INFO if config_name == "production" else logging.DEBUG
    if log_type is None:
        log_type = LoggerType.CONSOLE_FILE if config_name == "production" else LoggerType.CONSOLE
    return log_level, log_type, is_debug


def get_buffer_size() -> Tuple[Optional[int], Optional[int]]:
    max_buffer_size: Optional[Union[str, int]] = os.environ.get("MAX_BUFFER_SIZE") or ""
    max_body_size: Optional[Union[str, int]] = os.environ.get("MAX_BODY_SIZE") or ""
    max_buffer_size = None if not is_number(max_buffer_size) else int(max_buffer_size)
    max_body_size = None if not is_number(max_body_size) else int(max_body_size)
    return max_buffer_size, max_body_size


def get_cpu_limit() -> int:
    if os_name in ["windows", "unknown"]:
        # for windows os, just 1. test in win11
        return 1
    cpu_limit: int = 1 if not is_number(os.environ.get("MIO_LIMIT_CPU")) \
        else int(os.environ.get("MIO_LIMIT_CPU"))
    return cpu_limit
