# -*- coding: utf-8 -*-
import os
import sys
import yaml
import time
import codecs
import logging
from celery import Celery
from flask import Flask, blueprints
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_babel import Babel
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect
from flask_mongoengine import MongoEngine
from flask_redis import FlaskRedis
from flask_mail import Mail
from flask_caching import Cache
from tornado.ioloop import IOLoop
from typing import Tuple, Optional, List, Union
from mio.util.Helper import in_dict, is_enable, is_number
from mio.util.Logs import LogHandler, LoggerType, nameToLevel
from mio.sys.wsgi import MIO_SYSTEM_VERSION

mail: Optional[Mail] = None
crypt: Bcrypt = Bcrypt()
db: Optional[MongoEngine] = None
redis_db: Optional[FlaskRedis] = None
csrf: Optional[CSRFProtect] = None
login_manager: Optional[LoginManager] = None
cache: Optional[Cache] = None
babel: Optional[Babel] = None
celery_app: Optional[Celery] = None


def create_app(config_name: str, root_path: Optional[str] = None, config_clz: Optional[str] = None,
               logger_type: LoggerType = LoggerType,
               log_level: int = logging.DEBUG) -> Tuple[Flask, List[tuple], LogHandler]:
    global cache, babel, login_manager, csrf, redis_db, db, mail, celery_app
    console = LogHandler('PyMio', logger_type=logger_type, log_level=log_level)
    console.info(u'Initializing the system......profile: {}'.format(config_name))
    config_clz: str = 'config' if not isinstance(config_clz, str) else config_clz.strip()
    config_path: str = os.path.join(root_path, config_clz.replace('.', '/'))
    clazz = __import__(config_clz, globals(), fromlist=['config'])
    config: dict = getattr(clazz, 'config')
    yaml_file: str = os.path.join(config_path, 'config.yaml')
    if not os.path.isfile(yaml_file):
        console.error(u'config.yaml not found!')
        sys.exit(0)
    config_yaml: dict = yaml.load(codecs.open(yaml_file, 'r', 'utf-8'), Loader=yaml.FullLoader)
    if not in_dict(config_yaml, 'config'):
        console.error(u'config.yaml format error!')
        sys.exit(0)
    base_config: dict = config_yaml['config']
    static_folder: str = '{root_path}/web/static' if not in_dict(base_config, 'static_folder') \
        else base_config['static_folder']
    static_folder = static_folder.replace('{root_path}', root_path)
    static_folder = os.path.abspath(static_folder)
    if not os.path.isdir(static_folder):
        console.error(u'Static file path not found!')
        sys.exit(0)
    template_folder: str = '{root_path}/web/template' if not in_dict(base_config, 'template_folder') \
        else base_config['template_folder']
    template_folder = template_folder.replace('{root_path}', root_path)
    template_folder = os.path.abspath(template_folder)
    if not os.path.isdir(template_folder):
        console.error(u'Template path not found!')
        sys.exit(0)
    config_name: str = 'default' if not isinstance(config_name, str) else config_name
    config_name = config_name.lower()
    if not in_dict(config, config_name):
        console.error(u'Config invalid!')
        sys.exit(0)
    app: Flask = Flask(__name__, static_folder=static_folder, template_folder=template_folder)
    app.config.from_object(config[config_name])
    config[config_name].init_app(app)
    babel = Babel(app)
    if in_dict(base_config, 'csrf'):
        if is_enable(base_config['csrf'], 'enable'):
            csrf = CSRFProtect()
            csrf.init_app(app)
    if in_dict(base_config, 'login_manager'):
        if is_enable(base_config['login_manager'], 'enable'):
            login_manager_config: dict = base_config['login_manager']
            login_manager = LoginManager()
            login_manager.session_protection = 'strong' if not in_dict(login_manager_config, 'session_protection') \
                else login_manager_config['session_protection']
            login_manager.login_view = 'main.login' if not in_dict(login_manager_config, 'login_view') else \
                login_manager_config['login_view']
            if in_dict(login_manager_config, 'login_message'):
                login_manager.login_message = login_manager_config['login_message']
            if in_dict(login_manager_config, 'login_message_category'):
                login_manager.login_message_category = login_manager_config['login_message_category']
            login_manager.init_app(app)
    if is_enable(app.config, 'MIO_MAIL'):
        mail = Mail()
        mail.init_app(app)
    if is_enable(app.config, 'MONGODB_ENABLE'):
        db = MongoEngine()
        db.init_app(app)
    if is_enable(app.config, 'CELERY_ENABLE'):
        celery_app = Celery(
            app.import_name,
            broker=app.config['CELERY_BROKER_URL'],
            backend=app.config['CELERY_BACKEND_URL']
        )
    if is_enable(app.config, 'REDIS_ENABLE'):
        redis_db = FlaskRedis()
        redis_db.init_app(app)
    if is_enable(app.config, 'CORS_ENABLE'):
        if not in_dict(app.config, 'CORS_URI'):
            console.error(u'CORS_URI not define.')
            sys.exit(0)
        CORS(app, resources=app.config['CORS_URI'])
    if is_enable(app.config, 'CACHED_ENABLE'):
        cache = Cache(app)
    blueprints_config: List[dict] = config_yaml['blueprint'] if in_dict(config_yaml, 'blueprint') else []
    for blueprint in blueprints_config:
        key: str = list(blueprint.keys())[0]
        clazz = __import__(blueprint[key]['class'], globals(), fromlist=[key])
        bp: blueprints.Blueprint = getattr(clazz, key)
        if in_dict(blueprint[key], 'url_prefix'):
            app.register_blueprint(bp, url_prefix=blueprint[key]['url_prefix'])
        else:
            app.register_blueprint(bp)
    wss: List[tuple] = []
    websocket_config: List[dict] = config_yaml['websocket'] if in_dict(config_yaml, 'websocket') else []
    for websocket in websocket_config:
        key: str = list(websocket.keys())[0]
        clazz = __import__(websocket[key]['class'], globals(), fromlist=[key])
        ws = getattr(clazz, key)
        if not in_dict(websocket[key], 'path'):
            console.error('Path must be set in config.yaml.')
            sys.exit(0)
        wss.append((websocket[key]['path'], ws))
    return app, wss, console


def get_timezone_config() -> str:
    try:
        from config import Config
        tz: str = getattr(Config, 'MIO_TIMEZONE')
        return tz
    except Exception as e:
        str(e)
        return 'Asia/Shanghai'


def init_timezone():
    try:
        tz: str = get_timezone_config()
        os.environ['TZ'] = tz
        time.tzset()
    except Exception as e:
        str(e)


def init_uvloop():
    try:
        import uvloop
        import asyncio
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except Exception as e:
        str(e)
        IOLoop.configure('tornado.platform.asyncio.AsyncIOLoop')


def get_logger_level(config_name: str) -> Tuple[int, LoggerType, bool]:
    config_name = config_name.replace('\"', '').replace('\'', '').lower()
    is_debug = False if config_name == 'production' else True
    mio_logger_level: str = os.environ.get('MIO_LOGGER_LEVEL') or ''
    mio_logger_type: str = os.environ.get('MIO_LOGGER_TYPE') or ''
    log_level: Union[str, int] = logging.getLevelName(mio_logger_level)
    log_type: Optional[LoggerType] = nameToLevel.get(mio_logger_type)
    if not is_number(log_level):
        log_level = logging.INFO if config_name == 'production' else logging.DEBUG
    if log_type is None:
        log_type = LoggerType.CONSOLE_FILE if config_name == 'production' else LoggerType.CONSOLE
    return log_level, log_type, is_debug


def get_buffer_size() -> Tuple[Optional[int], Optional[int]]:
    max_buffer_size: Optional[Union[str, int]] = os.environ.get('MAX_BUFFER_SIZE') or ''
    max_body_size: Optional[Union[str, int]] = os.environ.get('MAX_BODY_SIZE') or ''
    max_buffer_size = None if not is_number(max_buffer_size) else int(max_buffer_size)
    max_body_size = None if not is_number(max_body_size) else int(max_body_size)
    return max_buffer_size, max_body_size


def get_cpu_limit() -> int:
    cpu_limit: int = 0 if not is_number(os.environ.get('MIO_LIMIT_CPU')) else int(os.environ.get('MIO_LIMIT_CPU'))
    return cpu_limit
