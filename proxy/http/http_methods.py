from typing import NamedTuple

HttpMethods = NamedTuple('HttpMethods', [
    ('GET', str),
    ('HEAD', str),
    ('POST', str),
    ('PUT', str),
    ('DELETE', str),
    ('CONNECT', str),
    ('OPTIONS', str),
    ('TRACE', str),
    ('PATCH', str),
])

httpMethods = HttpMethods(
    f'GET',
    f'HEAD',
    f'POST',
    f'PUT',
    f'DELETE',
    f'CONNECT',
    f'OPTIONS',
    f'TRACE',
    f'PATCH',
)