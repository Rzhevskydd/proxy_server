import socket
import ssl


def wrap_client_sock_to_ssl(sock: socket.socket, certfile: str) -> ssl.SSLSocket:
    pass


def wrap_server_sock_to_ssl(sock: socket.socket, ca_file: str) -> ssl.SSLSocket:
    pass

