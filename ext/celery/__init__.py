# -*- coding: utf-8 -*-
import sys
import click
from celery.__main__ import main
from flask.cli import AppGroup
from typing import List

CeleryCommand: AppGroup = AppGroup("celery", help="celery helper")


@CeleryCommand.command("run")
@click.option("-A", "--app", "clazz", default=None,
              help=u"APPLICATION.")
@click.option("-w", "--worker", "worker", default=None,
              help=u"Celery worker args.")
@click.option("-ctl", "--control", "control", default=None,
              help=u"Workers remote control args.")
def run(clazz=None, worker=None, control=None):
    if clazz is None:
        print(u"App must be set.")
        exit(0)
    cmd_lines: List[str] = ["celery", "-A", clazz]
    if worker is not None:
        cmd_lines.append("worker")
        tmp: List[str] = str(worker).split(" ")
        for _cmd_ in tmp:
            if len(_cmd_) <= 0:
                continue
            if _cmd_.find("=") >= 0:
                # FIXME 需要更优雅的方案
                _lins: List[str] = _cmd_.split("=")
                _an: str = _lins.pop(0)
                if len(_an) == 1:
                    # 不管什么原因，只要只有1个字符，就走-
                    _cmd_ = "-{} {}".format(_an, " ".join(_lins))
                else:
                    _cmd_ = "--{}={}".format(_an, "=".join(_lins))
            else:
                _cmd_ = "-" + _cmd_
            cmd_lines.append(_cmd_)
    elif control is not None:
        cmd_lines.append("control")
        tmp: List[str] = str(control).split(" ")
        for _cmd_ in tmp:
            if _cmd_.find("=") >= 0:
                # FIXME 需要更优雅的方案
                _lins: List[str] = _cmd_.split("=")
                _an: str = _lins.pop(0)
                if len(_an) == 1:
                    # 不管什么原因，只要只有1个字符，就走-
                    _cmd_ = "-{} {}".format(_an, " ".join(_lins))
                else:
                    _cmd_ = "--{}={}".format(_an, "=".join(_lins))
            else:
                _cmd_ = "-" + _cmd_
            cmd_lines.append(_cmd_)
    sys.argv = cmd_lines
    sys.exit(main())
