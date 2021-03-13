import socket
import ssl
from typing import Union


class TcpClientConnection:
    """An accepted client connection request."""

    def __init__(self,
                 conn: Union[ssl.SSLSocket, socket.socket],
                 addr):
        self.connection = conn
        self.address = addr
