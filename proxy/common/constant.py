DEFAULT_NUM_WORKERS = 1
DEFAULT_HTTP_PORT = 80
DEFAULT_TIMEOUT = 10
DEFAULT_BACKLOG = 100


PROXY_AGENT_HEADER_VALUE = b'Rzhevsky proxy'

CRLF = b'\r\n'
COLON = b':'
WHITESPACE = b' '
COMMA = b','
DOT = b'.'
SLASH = b'/'
HTTP_1_1 = b'HTTP/1.1'

PRIVATE_KEY_PATH = '/home/danil_rzhevsky/TECHOPARK/web_app_security/proxy_server/certs/localhost.key'
CERTS_MAIN_DIRNAME = '/home/danil_rzhevsky/TECHOPARK/web_app_security/proxy_server/certs'
EXT_FILENAME = "domains.ext"
CRT_FILENAME = "localhost.crt"
CSR_FILENAME = "localhost.csr"
ROOT_KEYNAME = "RootCA.key"
ROOT_CRTNAME = "RootCA.pem"
CERTS_DIRNAME = "certs"