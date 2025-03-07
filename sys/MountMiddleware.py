# -*- coding: UTF-8 -*-
from flask import Flask
from asgiref.wsgi import WsgiToAsgi
from hypercorn.typing import ASGIFramework


class MountMiddleware:
    def __init__(self, quart_app: ASGIFramework, wsgi_app: Flask):
        self._started = False
        self.quart_app = quart_app
        self.wsgi_app = WsgiToAsgi(wsgi_app)

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            await self.wsgi_app(scope, receive, send)
        elif scope["type"] == "lifespan":
            await self.quart_app(scope, receive, send)
            return
        else:
            await self.quart_app(scope, receive, send)
