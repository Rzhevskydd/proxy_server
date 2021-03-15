import multiprocessing
import socket
import threading
from multiprocessing import connection
from multiprocessing.synchronize import Lock

from multiprocessing.reduction import recv_handle
from typing import Optional


class Acceptor(multiprocessing.Process):
    def __init__(self,
                 idd: int,
                 work_queue: connection.Connection,
                 flags,
                 handler_klass,
                 lock: Lock
                 ) -> None:
        super().__init__()
        self.idd = idd
        self.work_queue: connection.Connection = work_queue
        self.flags = flags
        self.handler_klass = handler_klass
        self.lock = lock

        self.running = multiprocessing.Event()
        self.socket: Optional[socket.socket] = None

    def start_work(self, client_conn, client_addr):
        handler = self.handler_klass(
            client_conn=client_conn,
            client_addr=client_addr,
            flags=self.flags,
        )
        # work_thread = threading.Thread(target=handler.run)
        # work_thread.daemon = True
        # work_thread.start()
        handler.run()

    def accept_and_handle(self) -> None:
        with self.lock:
            assert self.socket
            client_conn, client_addr = self.socket.accept()
        self.start_work(client_conn, client_addr)

    def run(self) -> None:
        fd_from_work_queue = recv_handle(self.work_queue)
        self.work_queue.close()
        self.socket = socket.fromfd(fd_from_work_queue, socket.AF_INET, socket.SOCK_STREAM)

        while not self.running.is_set():
            self.accept_and_handle()


# while True:
#     try:
#         data = self.server.recv(DEFAULT_BUFF_SIZE)
#     except Exception as e:
#         count += 1
#         print('TIMEOUT  - ', e.args)
#         slice = data[-4:]
#         if slice == b'\r\n\r\n':
#             break
#         if count > 5:
#             print('VERY BAD - ', e.args)
#             self.shutdown()
#             self.client.close()
#             return
#     if not data:
#         break