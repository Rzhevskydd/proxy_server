import os
import pprint
import socket
import ssl
import time
from os import getpid
from typing import Optional, Union
from urllib import parse as urlparse

from http_parser.parser import HttpParser

from proxy.cert_utils import generate_cert
from proxy.common.constant import DEFAULT_HTTP_PORT, DEFAULT_TIMEOUT, PROXY_AGENT_HEADER_VALUE, PRIVATE_KEY_PATH, \
    ROOT_CRTNAME, CERTS_MAIN_DIRNAME
from proxy.http.http_methods import httpMethods
from proxy.http.utils import build_http_request, recv_and_parse, build_http_response

DEFAULT_BUFF_SIZE = 4096


class HttpProtocolHandler:

    PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT = build_http_response(
        200,
        reason=b'Connection established'
    )

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
            # self.initialize()

            client_data = recv_and_parse(self.client, self.request_parser, buff_size=DEFAULT_BUFF_SIZE)
            if len(client_data) == 0:
                print('Client closed connection')
                self.client.close()

            self.connect_upstream()

            if self.request_parser.get_method() == httpMethods.CONNECT:
                print(str(HttpProtocolHandler.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT))
                self.client.sendall(HttpProtocolHandler.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT)

                # Generate for each socket individual cert on fly
                cert_path = generate_cert(self.upstream_url.hostname)
                # TODO
                time.sleep(1)

                try:
                    # ctx = ssl.create_default_context()
                    # ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1
                    # ctx.load_cert_chain(certfile=cert_path, keyfile=PRIVATE_KEY_PATH)
                    # self.server = ctx.wrap_socket(self.server, server_hostname=self.upstream_url.hostname)

                    self.client = ssl.wrap_socket(self.client,
                                                  server_side=True,
                                                  certfile=cert_path,
                                                  keyfile=PRIVATE_KEY_PATH,
                                                  ssl_version=ssl.PROTOCOL_TLS)

                    client_data = recv_and_parse(self.client, self.request_parser, buff_size=DEFAULT_BUFF_SIZE)
                    ca_file = CERTS_MAIN_DIRNAME + '/' + ROOT_CRTNAME

                    # ctx = ssl.create_default_context(
                    #     ssl.Purpose.SERVER_AUTH, cafile=ca_file)
                    # ctx.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1
                    # ctx.check_hostname = True
                    # self.server.setblocking(True)
                    # self.server = ctx.wrap_socket(
                    #     self.server,
                    #     server_hostname=self.upstream_url.hostname)
                    # self.server.setblocking(False)

                    # require a certificate from the server
                    # self.server = ssl.wrap_socket(self.server,
                    #                            ca_certs=CERTS_MAIN_DIRNAME + '/' + ROOT_CRTNAME,
                    #                            cert_reqs=ssl.CERT_REQUIRED)
                    self.server = ssl.wrap_socket(self.server)

                    pprint.pprint(self.server.getpeercert())

                    proxy_req = build_http_request(
                        method=bytes(self.request_parser.get_method().encode()),
                        url=bytes(self.upstream_path.encode()),
                        proto_version=self.request_parser.get_version(),
                        headers=self.request_parser.get_headers(),

                        body=bytes(self.request_parser.recv_body())
                    )
                    self.server.sendall(proxy_req)

                    # response_data = recv_and_parse(self.server, self.response_parser, buff_size=DEFAULT_BUFF_SIZE)
                    response_data = bytes()
                    data = bytes()
                    while True:
                        data = self.server.recv(DEFAULT_BUFF_SIZE)
                        if not data:
                            break
                        response_data += data
                    self.total_response_size = len(response_data)
                    if len(response_data) == 0:
                        print('Server closed connection')
                        self.server.close()

                    self.client.sendall(response_data)

                except Exception as e:
                    print(e.args)

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
        if '443' in url:
            # костыль
            url = 'http://' + url.split(':')[0] + '/'
            DEFAULT_HTTP_PORT = 443

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







