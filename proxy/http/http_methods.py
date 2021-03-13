from typing import NamedTuple

HttpMethods = NamedTuple('HttpMethods', [
    ('GET', bytes),
    ('HEAD', bytes),
    ('POST', bytes),
    ('PUT', bytes),
    ('DELETE', bytes),
    ('CONNECT', bytes),
    ('OPTIONS', bytes),
    ('TRACE', bytes),
    ('PATCH', bytes),
])

httpMethods = HttpMethods(
    b'GET',
    b'HEAD',
    b'POST',
    b'PUT',
    b'DELETE',
    b'CONNECT',
    b'OPTIONS',
    b'TRACE',
    b'PATCH',
)