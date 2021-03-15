import socket
from typing import Tuple, Optional, Dict, Any, List

from http_parser.parser import HttpParser

from proxy.common.constant import WHITESPACE, CRLF, COLON, HTTP_1_1

http_header_delimiter = b'\r\n\r\n'
content_length_field = b'Content-Length:'


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
            tmp = headers[k].split(',')
            if len(tmp) == 2:
                headers[k] = tmp[1].strip()
            else:
                headers[k] = headers[k].split(':')[0].strip()
        req += build_http_header(k, headers[k]) + CRLF
    req += CRLF

    if body is not None:
        req += body
    return req


def recv(conn: socket.socket):
    http = HTTPResource('as', 'as')
    header, body = http.recv(conn)

    return header + body

    # data = bytes()
    # while True:
    #     data += conn.recv(buff_size)
    #     if not data:
    #         break
    #
    #     nrecvd = len(data)
    #     nparsed = parser.execute(data, nrecvd)
    #     assert nrecvd == nparsed
    #
    #     if parser.is_message_complete():
    #         break
    #
    # return data


def build_http_response(status_code: int,
                        protocol_version: bytes = b'HTTP/1.1',
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


class HTTPResource:
    ########################################

    http_header_delimiter = b'\r\n\r\n'
    content_length_field = b'Content-Length:'

    ########################################

    @classmethod
    def get(cls, host, resource):
        '''
        Creates a new HTTPResource with the given host and request, then tries
        to resolve the host, send the request and receive the response. The
        downloaded HTTPResource is then returned.
        '''
        http = cls(host, resource)
        port = 80
        try:
            ip = socket.gethostbyname(host)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp:
                tcp.connect((ip, port))
                http.send(tcp)
                http.recv(tcp)
        except Exception as e:
            raise e
        return http

    ####################

    @classmethod
    def read_until(cls, sock, condition, length_start=0, chunk_size=4096):
        '''
        Reads from the given socket until the condition returns True. Returns
        an array of bytes read from the socket.
        The condition should be a function that takes two parameters,
        condition(length, data), where length is the total number of bytes
        read and data is the most recent chunk of data read. Based on those two
        values, the condition must return True in order to stop reading from
        the socket and return the data read so far.
        '''
        data = bytes()
        chunk = bytes()
        length = length_start
        try:
            while not condition(length, chunk):
                chunk = sock.recv(chunk_size)
                if not chunk:
                    break
                else:
                    data += chunk
                    length += len(chunk)
        except socket.timeout:
            pass
        return data

    ####################

    @classmethod
    def formatted_http_request(cls, host, resource, method='GET'):
        '''
        Returns a sequence of bytes representing an HTTP request of the given
        method. Uses self.resource and self.host to build the HTTP headers.
        '''
        request = '{} {} HTTP/1.1\nhost: {}\n\n'.format(method,
                                                        resource,
                                                        host)
        return request.encode()

    ####################

    @classmethod
    def separate_header_and_body(cls, data):
        '''
        Returns a the tuple (header, body) from the given array of bytes. If
        the given array doesn't contain the end of header signal then it is
        assumed to be all header.
        '''
        try:
            index = data.index(cls.http_header_delimiter)
        except:
            return (data, bytes())
        else:
            index += len(cls.http_header_delimiter)
            return (data[:index], data[index:])

    ####################

    @classmethod
    def get_content_length(cls, header):
        '''
        Returns the integer value given by the Content-Length HTTP field if it
        is found in the given sequence of bytes. Otherwise returns 0.
        '''
        for line in header.split(b'\r\n'):
            if cls.content_length_field in line:
                return int(line[len(cls.content_length_field):])
        return 0

    ########################################

    def __init__(self, host, resource):
        self.host = host
        self.resource = resource
        self.header = bytes()
        self.content_length = 0
        self.body = bytes()

    ####################

    def end_of_header(self, length, data):
        '''
        Returns true if data contains the end-of-header marker.
        '''
        return b'\r\n\r\n' in data

    ####################

    def end_of_content(self, length, data):
        '''
        Returns true if length does not fullfil the content_length.
        '''
        return self.content_length <= length

    ####################

    def send(self, sock, method='GET'):
        '''
        Write an HTTP request, with the given method, to the given socket. Uses
        self.http_request to build the HTTP headers.
        '''
        sock.sendall(self.formatted_http_request(self.host,
                                                 self.resource,
                                                 method))

    ####################

    def recv(self, sock):
        '''
        Reads an HTTP Response from the given socket. Returns that response as a
        tuple (header, body) as two sequences of bytes.
        '''

        # read until at end of header
        self.data = self.read_until(sock, self.end_of_header)

        # separate our body and header
        self.header, self.body = self.separate_header_and_body(self.data)

        # get the Content Length from the header
        self.content_length = self.get_content_length(self.header)

        # read until end of Content Length
        self.body += self.read_until(sock, self.end_of_content, len(self.body))

        return (self.header, self.body)

