import os
import pprint
import socket
import ssl
import time
from http.client import HTTPResponse
from os import getpid
from string import Template
from subprocess import Popen, PIPE
from typing import Optional, Union
from urllib import parse as urlparse

from http_parser.pyparser import HttpParser

from proxy.cert_utils import generate_cert
from proxy.common.constant import DEFAULT_HTTP_PORT, DEFAULT_TIMEOUT, PROXY_AGENT_HEADER_VALUE, PRIVATE_KEY_PATH, \
    ROOT_CRTNAME, CERTS_DIR, SSL_HANDSHAKES_LIMIT_NUMBER, GENERATED_CERTS_DIR, CERT_KEY, CA_CERT, CA_KEY
from proxy.http.http_methods import httpMethods
from proxy.http.utils import build_http_request, recv, build_http_response, HTTPResource

DEFAULT_BUFF_SIZE = 1024 * 1024 * 15


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

        self.upstream: Optional[urlparse.SplitResultBytes] = None
        self.host = None
        self.port = None
        self.upstream_url = None

        self.server: Optional[socket.socket] = None

    def parse_url(self, parser):
        url = parser.get_url()
        method = parser.get_method()

        protocol_pos = url.find('://')
        if protocol_pos != -1:
            url = url[(protocol_pos + 3):]

        port_pos = url.find(':')
        host_pos = url.find('/')
        if host_pos == -1:
            host_pos = len(url)
        if port_pos == -1 or host_pos < port_pos:
            port = 443 if method == "CONNECT" else DEFAULT_HTTP_PORT
        else:
            port = int((url[port_pos + 1:])[:host_pos - port_pos - 1])

        port_ind = url.find(':')
        if port_ind != -1:
            url = url[:port_ind]

        self.upstream = urlparse.urlsplit('http://' + url + '/')
        self.upstream_url = self.build_upstream_relative_path()
        host = self.upstream.hostname

        port_ind = host.find(':')
        if port_ind != -1:
            host = host[:port_ind]

        return host, port

    def run(self) -> None:
        parser = HttpParser()
        try:
            client_data = recv(self.client)
            print('CONNECT:', str(client_data))
            if len(client_data) == 0:
                print('Client closed connection')
                self.client.close()
                return

            parser.execute(client_data, len(client_data))

            host, port = self.parse_url(parser)

            if parser.get_method() == httpMethods.CONNECT:
                # Generate for each socket individual cert on fly
                # cert_path = generate_cert(self.host)

                epoch = "%d" % (time.time() * 1000)
                cert_path = "%s/%s.crt" % (CERTS_DIR.rstrip('/') + '/' + GENERATED_CERTS_DIR, host)
                # CGenerating config to add subjectAltName (required in modern browsers)
                conf_template = Template("subjectAltName=DNS:${hostname}")
                conf_path = "%s/%s.cnf" % (CERTS_DIR.rstrip('/') + '/' + GENERATED_CERTS_DIR, host)
                with open(conf_path, 'w') as fp:
                    fp.write(conf_template.substitute(hostname=host))

                # Generating certificate
                p1 = Popen(["openssl", "req", "-new", "-key", CERTS_DIR + CERT_KEY,
                            "-subj", "/CN=%s" % host, "-addext",
                            "subjectAltName = DNS:" + host], stdout=PIPE)
                p2 = Popen(
                    ["openssl", "x509", "-req", "-extfile", conf_path, "-days", "3650",
                     "-CA", CERTS_DIR + CA_CERT,
                     "-CAkey", CERTS_DIR + CA_KEY,
                     "-set_serial", epoch,
                     "-out", cert_path], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()
                os.unlink(conf_path)

                tunn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                tunn.connect((host, port))

                connect_resp = HttpProtocolHandler.PROXY_TUNNEL_ESTABLISHED_RESPONSE_PKT
                self.client.sendall(connect_resp)

                try:
                    count = 0
                    while True:
                        try:
                            count += 1
                            self.client = ssl.wrap_socket(self.client,
                                                          server_side=True,
                                                          certfile=cert_path,
                                                          keyfile=CERTS_DIR + CERT_KEY)
                            # self.client.do_handshake()
                            break
                        except Exception as e:
                            if count > SSL_HANDSHAKES_LIMIT_NUMBER:
                                print('SHUTDOWN - ', e.args)
                                self.shutdown()
                                self.client.close()
                                return
                            print(count)
                            time.sleep(0.01)  # 100 ms

                    # request = recv(self.client)
                    request = self.client.recv(40960)

                    # proxy_req = build_http_request(
                    #     method=bytes(parser.get_method().encode()),
                    #     url=bytes(self.upstream_path.encode()),
                    #     proto_version=parser.get_version(),
                    #     headers=parser.get_headers(),
                    #
                    #     body=bytes(self.request_parser.recv_body())
                    # )
                    print('REQUEST TO SERVER:', str(request))
                    self.server = ssl.wrap_socket(tunn)
                    self.server.send(request)

                    http = HTTPResource('as', 'as')
                    header, body = http.recv(self.server)
                    response_data = header + body

                    self.total_response_size = len(response_data)
                    if len(response_data) == 0:
                        print('Server closed connection')
                        self.server.close()
                        return

                    # print('RESPONSE DATA: ', str(response_data))
                    self.client.sendall(response_data)

                except Exception as e:
                    print(e.args)

            elif self.server:
                via_header = (b'Via', b'%s' % PROXY_AGENT_HEADER_VALUE)

                proxy_req = build_http_request(
                    method=bytes(parser.get_method().encode()),
                    url=bytes(self.upstream_url.encode()),
                    proto_version=parser.get_version(),
                    headers=parser.get_headers(),
                    body=bytes(parser.recv_body())
                )

                self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server.connect((host, port))
                self.server.sendall(proxy_req)

                response_data = recv(self.server)
                self.total_response_size = len(response_data)
                if len(response_data) == 0:
                    print('Server closed connection')
                    self.server.close()
                    return

                self.client.sendall(response_data)

        except Exception as e:
            print(e.args)
            pass

        finally:
            self.shutdown()

    def connect_upstream(self, parser) -> None:
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.connect((host, int(port)))
        # self.server.settimeout(DEFAULT_TIMEOUT)

        self.host, self.port = host, port

    def build_upstream_relative_path(self) -> Union[str, bytes]:
        if not self.upstream:
            return f'/None'
        url = self.upstream.path
        if not self.upstream.query == '':
            url += f'?' + str(self.upstream.query)
        if not self.upstream.fragment == '':
            url += f'#' + str(self.upstream)
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
            # self.access_log()
            self.server.close()

    def access_log(self):
        server_host, server_port = self.upstream.hostname, self.upstream.port \
            if self.upstream.port else DEFAULT_HTTP_PORT

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







