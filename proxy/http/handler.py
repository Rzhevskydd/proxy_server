import os
import pprint
import socket
import ssl
import sys
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
                 flags,
                 req):
        self.start_time: float = time.time()

        self.client = client_conn
        self.req = req

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
        p = HttpParser()
        try:
            p.execute(self.req, len(self.req))

            url = p.get_url()
            metopd = p.get_method()

            http_pos = url.find('://')
            if http_pos == -1:
                temp = url
            else:
                temp = url[(http_pos + 3):]

            port_pos = temp.find(':')
            host_pos = temp.find('/')
            if host_pos == -1:
                host_pos = len(temp)
            if port_pos == -1 or host_pos < port_pos:
                port = 443 if metopd == "CONNECT" else 80
            else:
                port = int((temp[port_pos + 1:])[:host_pos - port_pos - 1])

            host = p.get_headers()['host']
            port_ind = host.find(':')
            if port_ind != -1:
                host = host[:port_ind]
            if metopd == "CONNECT":
                https_proxy(host, port, self.client)
            else:
                proxy(host, port, self.client, self.req)
        except Exception as e:
            print(e)
            pass

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


cert_key = 'certs/cert.key'
ca_key = 'certs/ca.key'
ca_cert = 'certs/ca.crt'
cert_dir = 'certs/generated_certs/'
buffer_size = 8192


def https_proxy(host, port, conn):
    epoch = "%d" % (time.time() * 1000)
    cert_path = "%s/%s.crt" % (cert_dir.rstrip('/'), host)
    # CGenerating config to add subjectAltName (required in modern browsers)
    conf_template = Template("subjectAltName=DNS:${hostname}")
    conf_path = "%s/%s.cnf" % (cert_dir.rstrip('/'), host)
    with open(conf_path, 'w') as fp:
        fp.write(conf_template.substitute(hostname=host))

    # Generating certificate
    p1 = Popen(["openssl", "req", "-new", "-key", cert_key, "-subj", "/CN=%s" % host, "-addext",
                "subjectAltName = DNS:" + host], stdout=PIPE)
    p2 = Popen(
        ["openssl", "x509", "-req", "-extfile", conf_path, "-days", "3650", "-CA", ca_cert, "-CAkey", ca_key,
         "-set_serial", epoch,
         "-out", cert_path], stdin=p1.stdout, stderr=PIPE)
    p2.communicate()
    os.unlink(conf_path)

    # Connecting to server
    tunn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tunn.connect((host, port))
    # Establishing connection with client
    conn.sendall(b'HTTP/1.1 200 Connection Established\r\n\r\n')
    conn_s = ssl.wrap_socket(conn, keyfile=cert_key, certfile=cert_path, server_side=True)
    conn_s.do_handshake()

    request = conn_s.recv(40960)
    # Establishing https connection with server
    # context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    # s_sock = context.wrap_socket(tunn, server_hostname=host)
    s_sock = ssl.wrap_socket(tunn)
    s_sock.send(request)
    # Getting response
    parser = HttpParser()
    resp = b''
    while True:
        data = s_sock.recv(buffer_size)
        if not data:
            break

        received = len(data)
        _ = parser.execute(data, received)
        resp += data

        if parser.is_message_complete():
            break

    conn_s.sendall(resp)
    # # Save information about request
    # sql_conn = saver.get_connection()
    # saver.save_request(sql_conn, host, port, request, 1)
    # sql_conn.close()

    s_sock.close()
    conn_s.close()


def proxy(host, port, conn, data):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((host, port))
        s.send(data)

        while True:
            reply = s.recv(buffer_size)

            if len(reply) > 0:
                conn.send(reply)
            else:
                break

        s.close()
        conn.close()
        # sql_conn = saver.get_connection()
        # saver.save_request(sql_conn, host, port, data, 0)
        # sql_conn.close()
    except socket.error:
        s.close()
        conn.close()
        sys.exit(1)