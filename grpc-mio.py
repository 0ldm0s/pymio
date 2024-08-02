#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import os
import sys
import codecs
import grpc
from concurrent import futures
from typing import Union
import grpc_greeter.calculator_pb2 as calculator_pb2
import grpc_greeter.calculator_pb2_grpc as calculator_pb2_grpc
from mio.sys import init_timezone, init_uvloop, MIO_SYSTEM_VERSION
from mio.util.Logs import LogHandler

sys.stdout = codecs.getwriter('utf8')(sys.stdout)
sys.stderr = codecs.getwriter('utf8')(sys.stderr)
root_path: str = os.path.abspath(os.path.dirname(__file__) + "/../")
sys.path.append(root_path)


class CalculatorServicer(calculator_pb2_grpc.CalculatorServicer):
    def Add(self, request, context):
        result = request.num1 + request.num2
        return calculator_pb2.AddResponse(result=result)


MIO_UVLOOP: Union[str, bool] = str(os.environ.get("MIO_UVLOOP", "0"))
MIO_UVLOOP = True if MIO_UVLOOP == "1" else False
init_timezone()
if MIO_UVLOOP:
    init_uvloop()


def gserve():
    console_log = LogHandler("PyMio")
    try:
        console_log.info(f"Pymio Version: {MIO_SYSTEM_VERSION}")
        server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
        calculator_pb2_grpc.add_CalculatorServicer_to_server(CalculatorServicer(), server)
        server.add_insecure_port("unix:///tmp/test.sock")
        server.start()
        server.wait_for_termination()
    except KeyboardInterrupt:
        pass
    finally:
        console_log.info("gRPC Server Closed.")


if __name__ == "__main__":
    gserve()
