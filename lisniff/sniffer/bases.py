import socket
from lisniff.packet.bases import PacketParser
from .interfaces import ISniffer


class Sniffer(ISniffer):
    def __init__(self):
        self.__queue = None
        self.__parser = PacketParser()
        self.__raw_socket = None
        self.__port = 443
        self.__is_running = False

    def setup_sniffer(self) -> None:
        self.__raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

    def run(self):
        if not self.__raw_socket:
            self.setup_sniffer()
            
        self.__is_running = True
        while(self.__is_running):
            data = self.__raw_socket.recvfrom(self.__port)
            
            ### TODO:
            # before parsing, we move raw data to queue to prevent blocking
            packet = self.__parser.parse(data[0])
            
            ### TODO:
            # trigger event when parsing is completed
            print(packet.get_destination_mac_ip())
