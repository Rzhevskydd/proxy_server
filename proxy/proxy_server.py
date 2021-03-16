import sys
import socket
from typing import Optional

from proxy.common.arg_parser import arg_parser
from proxy.core.acceptor import AcceptorPool
from proxy.http.handler import HttpProtocolHandler


class ProxyServer:

    handler_class = HttpProtocolHandler

    def __init__(self, flags):
        self.flags = flags
        self.socket = None
        self.acceptors: Optional[AcceptorPool] = None

    def start(self):
        self.acceptors = AcceptorPool(self.flags)
        self.acceptors.setup()


def entry_point() -> None:
    env_args = sys.argv[1:]
    # TODO: add cert file
    flags = arg_parser.parse_args(env_args)

    proxy = ProxyServer(flags)
    proxy.start()
