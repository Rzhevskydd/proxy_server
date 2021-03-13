import argparse
import socket

from multiprocessing.reduction import send_handle
from multiprocessing import connection, Pipe, Lock
from typing import List, Optional

from proxy.core.acceptor.acceptor import Acceptor
from proxy.http.handler import HttpProtocolHandler


LOCK = Lock()


class AcceptorPool:
    def __init__(self, flags: argparse.Namespace):
        self.flags = flags
        self.handler_class = HttpProtocolHandler
        self.socket: Optional[socket.socket] = None
        self.acceptors: List[Acceptor] = []
        self.work_queues: List[connection.Connection] = []

    def listen(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
        self.socket.bind((str(self.flags.hostname), self.flags.port))
        self.socket.listen(self.flags.backlog)
        # self.socket.setblocking(False)

        print(f'Listening on {self.flags.hostname} : {self.flags.port}')

    def start_workers(self):
        # if self.flags.num_workers == 1:
        #     while True:
        #         client_conn, client_addr = self.socket.accept()
        #         handler = self.handler_class(client_conn, client_addr, self.flags)
        #         handler.run()

        for acceptor_id in range(self.flags.num_workers):
            work_queue = Pipe()
            acceptor = Acceptor(
                idd=acceptor_id,
                work_queue=work_queue[1],
                flags=self.flags,
                handler_klass=self.handler_class,
                lock=LOCK
            )
            acceptor.start()
            print(f'start acceptor #{acceptor_id}, {acceptor.pid}')
            self.acceptors.append(acceptor)
            self.work_queues.append(work_queue[0])

    def setup(self):
        self.listen()
        self.start_workers()

        assert self.socket is not None
        # if self.flags.num_workers == 1:
        #     self.socket.close()
        #     return
        for idx in range(self.flags.num_workers):
            send_handle(
                self.work_queues[idx],
                self.socket.fileno(),
                self.acceptors[idx].pid
            )
            self.work_queues[idx].close()
        self.socket.close()
