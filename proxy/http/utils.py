import socket
from typing import Tuple, Optional, Dict, Any, List

from http_parser.parser import HttpParser

from proxy.common.constant import WHITESPACE, CRLF, COLON, HTTP_1_1


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
        if '443' in headers[k]:
            headers[k] = headers[k].split(',')[1].strip()
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


def build_http_response(status_code: int,
                        protocol_version: bytes = HTTP_1_1,
                        reason: Optional[bytes] = None,
                        headers: Optional[Dict[bytes, bytes]] = None,
                        body: Optional[bytes] = None) -> bytes:
    """Build and returns a HTTP response packet."""
    line = [protocol_version, bytes_(status_code)]
    if reason:
        line.append(reason)
    if headers is None:
        headers = {}
    has_content_length = False
    has_transfer_encoding = False
    for k in headers:
        if k.lower() == b'content-length':
            has_content_length = True
        if k.lower() == b'transfer-encoding':
            has_transfer_encoding = True
    if body is not None and \
            not has_transfer_encoding and \
            not has_content_length:
        headers[b'Content-Length'] = bytes_(len(body))
    return build_http_pkt(line, headers, body)


def bytes_(s: Any, encoding: str = 'utf-8', errors: str = 'strict') -> Any:
    """Utility to ensure binary-like usability.

    If s is type str or int, return s.encode(encoding, errors),
    otherwise return s as it is."""
    if isinstance(s, int):
        s = str(s)
    if isinstance(s, str):
        return s.encode(encoding, errors)
    return s


def build_http_pkt(line: List[bytes],
                   headers: Optional[Dict[bytes, bytes]] = None,
                   body: Optional[bytes] = None) -> bytes:
    """Build and returns a HTTP request or response packet."""
    req = WHITESPACE.join(line) + CRLF
    if headers is not None:
        for k in headers:
            req += build_http_header(k, headers[k]) + CRLF
    req += CRLF
    if body:
        req += body
    return req