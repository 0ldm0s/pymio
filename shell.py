#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys
import codecs

root_path: str = os.path.abspath(os.path.dirname(__file__) + "/../")
sys.path.append(root_path)
from mio.pymio import app
from mio.ext.cli import CliCommand
from mio.ext.celery import CeleryCommand

sys.stdout = codecs.getwriter('utf8')(sys.stdout)
sys.stderr = codecs.getwriter('utf8')(sys.stderr)
app.cli.add_command(CliCommand)
app.cli.add_command(CeleryCommand)
