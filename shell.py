#!/usr/bin/env python
# -*- coding: utf-8 -*-
from mio.cli import app
from mio.ext.cli import CliCommand
from mio.ext.celery import CeleryCommand

app.cli.add_command(CliCommand)
app.cli.add_command(CeleryCommand)
