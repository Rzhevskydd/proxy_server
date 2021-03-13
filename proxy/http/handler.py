import socket
import time
from os import getpid
from typing import Optional, Union
from urllib import parse as urlparse

from http_parser.parser import HttpParser

from proxy.common.constant import DEFAULT_HTTP_PORT, DEFAULT_TIMEOUT, PROXY_AGENT_HEADER_VALUE
from proxy.http.http_methods import httpMethods
from proxy.http.utils import build_http_request, recv_and_parse

DEFAULT_BUFF_SIZE = 4096


class HttpProtocolHandler:
    def __init__(self,
                 client_conn: socket.socket,
                 client_addr,
                 flags):
        self.start_time: float = time.time()

        self.client = client_conn
        self.client_addr = client_addr  # host and socket_fd
        self.flags = flags

        self.request_parser = HttpParser(0)  # 0 - parse only requests
        self.response_parser = HttpParser(1)  # 1 - parse only responses
        self.total_response_size: int = 0

        self.upstream_url: Optional[urlparse.SplitResultBytes] = None
        self.upstream_path = None

        self.server: Optional[socket.socket] = None

    def run(self) -> None:
        try:
            self.initialize()

            client_data = recv_and_parse(self.client, self.request_parser, buff_size=DEFAULT_BUFF_SIZE)
            if len(client_data) == 0:
                print('Client closed connection')
                self.client.close()

            self.connect_upstream()

            if self.request_parser.get_method() == httpMethods.CONNECT:
                pass
            elif self.server:
                via_header = (b'Via', b'%s' % PROXY_AGENT_HEADER_VALUE)

                proxy_req = build_http_request(
                    method=bytes(self.request_parser.get_method().encode()),
                    url=bytes(self.upstream_path.encode()),
                    proto_version=self.request_parser.get_version(),
                    headers=self.request_parser.get_headers(),
                    body=bytes(self.request_parser.recv_body())
                )
                self.server.sendall(proxy_req)

                response_data = recv_and_parse(self.server, self.response_parser, buff_size=DEFAULT_BUFF_SIZE)
                self.total_response_size = len(response_data)
                if len(response_data) == 0:
                    print('Server closed connection')
                    self.server.close()

                self.client.sendall(response_data)

        except Exception as e:
            print(e.args)
            pass

        finally:
            self.shutdown()

    def connect_upstream(self) -> None:
        url = self.request_parser.get_url()
        self.upstream_url = urlparse.urlsplit(url)
        self.upstream_path = self.build_upstream_relative_path()
        host, port = self.upstream_url.hostname, self.upstream_url.port \
            if self.upstream_url.port else DEFAULT_HTTP_PORT

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.connect((host, int(port)))
        # self.server_conn.settimeout(DEFAULT_TIMEOUT)

    def build_upstream_relative_path(self) -> Union[str, bytes]:
        if not self.upstream_url:
            return b'/None'
        url = self.upstream_url.path
        if not self.upstream_url.query == '':
            url += b'?' + self.upstream_url.query
        if not self.upstream_url.fragment == '':
            url += b'#' + self.upstream_url.fragment
        return url

    def shutdown(self):
        if self.server is None:
            return

        try:
            pass
            self.server.shutdown(socket.SHUT_WR)
        except OSError:
            pass
        finally:
            self.access_log()
            self.server.close()

    def access_log(self):
        server_host, server_port = self.upstream_url.hostname, self.upstream_url.port \
            if self.upstream_url.port else DEFAULT_HTTP_PORT

        connection_time_ms = (time.time() - self.start_time) * 1000
        method = self.request_parser.get_method()
        if method == httpMethods.CONNECT:
            pass
        elif method:
            print(
                'pid:%s |  %s:%s - %s %s:%s%s - %s %s - %s bytes - %.2f ms' %
                (str(getpid()),
                 self.client_addr[0], self.client_addr[1],
                 method,
                 server_host, server_port,
                 self.request_parser.get_path(),
                 self.response_parser.get_status_code(),
                 self.response_parser.get_errno(),
                 self.total_response_size,
                 connection_time_ms)
            )

    def initialize(self):
        """Optionally upgrades connection to HTTPS, set conn in non-blocking mode."""
        conn = self.optionally_wrap_socket(self.client)

    def optionally_wrap_socket(self, conn: socket.socket) -> socket.socket:
        if self.encryption_enabled():
            assert self.flags.keyfile and self.flags.certfile
            conn = wrap_socket(conn, self.flags.keyfile, self.flags.certfile)
        return conn

    def encryption_enabled(self) -> bool:
        return self.flags.keyfile is not None and \
               self.flags.certfile is not None







