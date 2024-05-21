import threading
import queue
import socket
from lisniff.packet.bases import PacketParser
from .interfaces import ISniffer


class Sniffer(ISniffer):
    def __init__(self):
        self.__queue = queue.Queue()
        self.__parser = PacketParser()
        self.__raw_socket = None
        self.__port = 443
        self.__is_running = False
        self.__worker_thread = None

    def setup_sniffer(self) -> None:
        self.__raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        self.__worker_thread = threading.Thread(target=self.process, daemon=True)
        
    def start_worker(self):
        self.__worker_thread.start()
        
    def process(self):
        while True:
            data = self.__queue.get()
            self.__queue.task_done()

    def run(self):
        if not self.__raw_socket:
            self.setup_sniffer()
            self.start_worker()
            
        self.__is_running = True
        while(self.__is_running):
            data = self.__raw_socket.recvfrom(self.__port)
            self.__queue.put(data)
            
        self.__queue.join()
