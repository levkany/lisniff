import threading
import queue
import socket
from lisniff.packet.bases import PacketParser
from lisniff.packet.bases import InternetPacketParser
from .interfaces import ISniffer
from lisniff import events
from lisniff.logger import lisniff_logger


class Sniffer(ISniffer):
    def __init__(self):
        self.__queue = queue.Queue()
        self.__total_processed = 0
        self.__parser = PacketParser()
        self.__internet_packet_parser = InternetPacketParser()
        self.__raw_socket = None
        self.__port = 443
        self.__is_running = False
        self.__worker_thread = None
        self.__registered_events = {}
        self.__logger = None
        self.setup_logger()
        
    def setup_logger(self):
        self.__logger = lisniff_logger

    def setup_sniffer(self) -> None:
        self.__logger.debug("setting up lisniff ..")
        self.__raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
        self.__logger.debug("main socket created and ready ..")
        self.__worker_thread = threading.Thread(target=self.process, daemon=True)
        self.__logger.debug("worker thread created and ready ..")
        
    def get_total_packets_processed(self) -> int:
        return self.__total_processed

    def get_total_packets_awaiting(self) -> int:
        return self.__queue.qsize()
        
    def get_logger(self):
        return self.__logger
        
    def start_worker(self):
        self.__logger.debug("starting worker ..")
        self.__worker_thread.start()
        
    def add_event_listener(self, event:str, fn:callable):
        self.__registered_events[event] = fn
        self.__logger.debug(f"added new event listener: \"{event}\"")
        
    def remove_event_listener(self, event:str):
        self.__registered_events.pop(event)
        self.__logger.debug(f"removed event listener: \"{event}\"")
        
    def trigger_event(self, event:str, *args, **kwargs):
        self.__registered_events[event](*args, **kwargs)
        self.__logger.debug(f"event: \"{event}\" triggerd")

    def process(self):
        while True:
            data = self.__queue.get()
            packet = self.__parser.parse(data)
            self.__queue.task_done()
            self.__total_processed += 1
            self.trigger_event(events.PACKET_PROCESSED, packet=packet)
            
            if packet.get_ether_type() == "0800":
                internet_packet = self.__internet_packet_parser.parse(packet.get_raw_payload())
                internet_packet.set_destination_mac_ip(packet.get_destination_mac_ip())
                internet_packet.set_source_mac_ip(packet.get_source_mac_ip())
                internet_packet.set_ether_type(packet.get_ether_type())
                internet_packet.set_checksum(packet.get_checksum())
                self.trigger_event(events.IPV4_PACKET_PROCESSED, packet=internet_packet)

    def run(self):
        if not self.__raw_socket:
            self.setup_sniffer()
            self.start_worker()
            
        self.__is_running = True
        self.__logger.info(f"lisniff is now running ...")
        while(self.__is_running):
            data = self.__raw_socket.recvfrom(self.__port)
            self.__logger.debug(f"recieved packet from port: \"{self.__port}\"")
            self.__queue.put(data[0])
            
        self.__queue.join()

    def on(self, event):
        def wrapper(fn):
            self.add_event_listener(event, fn)
            return fn            
        return wrapper
