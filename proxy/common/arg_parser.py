import argparse

from proxy.common.constant import DEFAULT_NUM_WORKERS, DEFAULT_BACKLOG

arg_parser = argparse.ArgumentParser()

arg_parser.add_argument(
    '--hostname',
    type=str,
    default='127.0.0.1'
)

arg_parser.add_argument(
    '--port',
    type=int,
    default=8080
)

arg_parser.add_argument(
    '--num-workers',
    type=int,
    default=DEFAULT_NUM_WORKERS,
)

arg_parser.add_argument(
    '--backlog',
    type=int,
    default=DEFAULT_BACKLOG,
    help='Default: 100. Maximum number of pending connections to proxy server')

arg_parser.add_argument(
    '--keyfile',
    type=str,
    default=None,
)

arg_parser.add_argument(
    '--certfile',
    type=str,
    default=None,
)