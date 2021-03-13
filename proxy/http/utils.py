import socket
from typing import Tuple

from http_parser.parser import HttpParser

from proxy.common.constant import WHITESPACE, CRLF, COLON


def build_http_header(k, value) -> bytes:
    if isinstance(k, str) and isinstance(value,str):
        return bytes(k.encode()) + COLON + WHITESPACE + bytes(value.encode())
    return k + COLON + WHITESPACE + value


def build_http_request(method: bytes,
                       url: bytes,
                       proto_version: Tuple[int, int],
                       headers=None,
                       body=None) -> bytes:
    if headers is None:
        headers = {}

    version = b'HTTP/%s.%s' % (str(proto_version[0]).encode(), str(proto_version[1]).encode())
    req = WHITESPACE.join([method, url, version]) + CRLF
    for k in headers:
        req += build_http_header(k, headers[k]) + CRLF
        req += CRLF

    if body is not None:
        req += body
    return req


def recv_and_parse(conn: socket.socket, parser: HttpParser, buff_size: int) -> bytes:
    data = bytes()
    while True:
        data += conn.recv(buff_size)
        if not data:
            break

        nrecvd = len(data)
        nparsed = parser.execute(data, nrecvd)
        assert nrecvd == nparsed

        if parser.is_message_complete():
            break

    return data

