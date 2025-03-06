# -*- coding: UTF-8 -*-
import os
import rtoml
import codecs
import inspect
from flask import Flask
from typing import Dict
from mio.util.Logs import LogHandler
from mio.util.Helper import get_root_path


class LocalTextHelper:
    _lang_dict: Dict = {}
    _default_language: str = "zh-CN"

    def __get_logger__(self, name: str) -> LogHandler:
        name = f"{self.__class__.__name__}.{name}"
        return LogHandler(name)

    # 这个是新的翻译容器
    def __init__(self, app: Flask, translations_path: str = "translations"):
        if "DEFAULT_LANGUAGE" in app.config:
            _default_language = app.config["DEFAULT_LANGUAGE"]
        translations_path = os.path.join(get_root_path(), translations_path)
        if not os.path.isdir(translations_path):
            raise Exception("translations path not exist.")
        # 遍历文件夹，找到所有的toml
        translation_files = os.listdir(translations_path)
        for _file in translation_files:
            if not _file.endswith(".toml"):
                continue
            base_name, *_ = _file.split(".")
            _file = os.path.join(translations_path, _file)
            if os.path.isdir(_file):
                continue
            config_toml = rtoml.load(
                codecs.open(_file, "r", "UTF-8").read())
            for k, v in config_toml.items():
                self._lang_dict[f"{base_name}.{k}"] = v

    def get_text(self, msg_id: str, lang: str) -> str:
        console_log = self.__get_logger__(inspect.stack()[0].function)
        if msg_id not in self._lang_dict:
            console_log.error(f"[{msg_id}]未能找到对应的变量")
            return ""
        msg: dict = self._lang_dict[msg_id]
        if lang not in msg:
            console_log.warning(f"[{msg_id}]未能找到对应的[{lang}]，更换为默认[{self._default_language}]")
            lang = self._default_language
        if lang not in msg:
            console_log.error(f"[{msg_id}]未能找到对应的[{lang}]")
            return ""
        return msg[lang]
