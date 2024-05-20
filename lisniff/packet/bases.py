import binascii
import struct
from .interfaces import IPacket
from .interfaces import IPacketParser
from .types import MacIP
from .types import EtherType
from .types import ether_types
from lisniff.utils import format_mac_ip


class Packet(IPacket):
    def __init__(self):
        self.__destination_mac_ip = None
        self.__source_mac_ip = None
        self.__raw_payload = None
        self.__ether_type = None
    
    def set_destination_mac_ip(self, mac_ip:MacIP) -> None:
        self.__destination_mac_ip = mac_ip
        
    def get_destination_mac_ip(self) -> MacIP | None:
        return self.__destination_mac_ip
        
    def get_source_mac_ip(self) -> MacIP | None:
        return self.__source_mac_ip
        
    def set_source_mac_ip(self, mac_ip:MacIP) -> None:
        self.__source_mac_ip = mac_ip        
        
    def get_raw_payload(self) -> bytes | None:
        return self.__raw_payload
    
    def set_raw_payload(self, raw_payload:bytes) -> None:
        self.__raw_payload = raw_payload
        
    def get_ether_type(self) -> EtherType | None:
        return self.__ether_type
        
    def set_ether_type(self, ether_type:EtherType) -> None:
        self.__ether_type = ether_type

class PacketParser(IPacketParser):
    def __init__(self, raw_data:bytes=None):
        self.raw_data = raw_data
    
    def parse(self, raw_data:bytes=None) -> Packet:
        data = raw_data or self.raw_data
        header = data[0:14]
        
        eth_hdr = struct.unpack("!6s6s2s", header)
        mac_ip = MacIP(format_mac_ip(binascii.hexlify(eth_hdr[0])))
        mac_s_ip = MacIP(format_mac_ip(binascii.hexlify(eth_hdr[1])))
        ether_type = EtherType(ether_types[(binascii.hexlify(eth_hdr[2]).decode('UTF-8'))])
        data_bytes = data[15:-4]
        
        packet = Packet()
        packet.set_destination_mac_ip(mac_ip)
        packet.set_source_mac_ip(mac_s_ip)
        packet.set_ether_type(ether_type)
        packet.set_raw_payload(data_bytes)
        
        return packet
