import binascii
import struct
from .interfaces import IPacket
from .interfaces import IInternetPacket
from .interfaces import IPacketParser
from .types import MacIP
from .types import EtherType
from lisniff.utils import format_mac_ip


class Packet(IPacket):
    def __init__(self):
        self.__destination_mac_ip = None
        self.__source_mac_ip = None
        self.__raw_payload = None
        self.__ether_type = None
        self.__checksum = None
        
    def set_checksum(self, checksum:str) -> None:
        self.__checksum = checksum
        
    def get_checksum(self) -> str | None:
        return self.__checksum
    
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


class InternetPacket(Packet, IInternetPacket):
    def __init__(self):
        super().__init__()
        self.__version:int = None
        self.__ihl:str = None
        self.__tos:int = None
        self.__total_length:int = None
        self.__identification:int = None
        self.__ttl:int = None
        self.__protocol:int = None
        self.__header_checksum:int = None
        self.__source_ip:str = None
        self.__dest_ip:str = None
        self.__payload:bytes = None
        
    def get_payload(self) -> bytes | None:
        return self.__payload
    
    def set_payload(self, payload:bytes) -> None:
        self.__payload = payload
        
    def get_version(self) -> str | None:
        return self.__version
    
    def set_version(self, version: int) -> None:
        self.__version = version

    def get_ihl(self) -> str | None:
        return self.__ihl

    def set_ihl(self, ihl: str) -> None:
        self.__ihl = ihl

    def get_tos(self) -> int | None:
        return self.__tos

    def set_tos(self, tos: int) -> None:
        self.__tos = tos

    def get_total_length(self) -> int | None:
        return self.__total_length

    def set_total_length(self, total_length: int) -> None:
        self.__total_length = total_length

    def get_identification(self) -> int | None:
        return self.__identification

    def set_identification(self, identification: int) -> None:
        self.__identification = identification

    def get_ttl(self) -> int | None:
        return self.__ttl

    def set_ttl(self, ttl: int) -> None:
        self.__ttl = ttl

    def get_protocol(self) -> int | None:
        return self.__protocol

    def set_protocol(self, protocol: int) -> None:
        self.__protocol = protocol

    def get_header_checksum(self) -> int | None:
        return self.__header_checksum

    def set_header_checksum(self, header_checksum: int) -> None:
        self.__header_checksum = header_checksum

    def get_source_ip(self) -> str | None:
        return self.__source_ip

    def set_source_ip(self, source_ip: str) -> None:
        self.__source_ip = source_ip

    def get_dest_ip(self) -> str | None:
        return self.__dest_ip

    def set_dest_ip(self, dest_ip: str) -> None:
        self.__dest_ip = dest_ip


class PacketParser(IPacketParser):
    def __init__(self, raw_data:bytes=None):
        self.raw_data = raw_data
    
    def parse(self, raw_data:bytes=None) -> Packet:
        data = raw_data or self.raw_data
        header = data[0:14]
        
        eth_hdr = struct.unpack("!6s6s2s", header)
        mac_ip = MacIP(format_mac_ip(binascii.hexlify(eth_hdr[0])))
        mac_s_ip = MacIP(format_mac_ip(binascii.hexlify(eth_hdr[1])))
        ether_type = binascii.hexlify(eth_hdr[2]).decode('UTF-8')
        data = data[14:-4]
        checksum = binascii.hexlify(struct.unpack("!4s", data[-4:])[0]).decode("utf-8")
        
        packet = Packet()
        packet.set_destination_mac_ip(mac_ip)
        packet.set_source_mac_ip(mac_s_ip)
        packet.set_ether_type(ether_type)
        packet.set_raw_payload(data)
        packet.set_checksum(checksum)
        
        return packet


class InternetPacketParser(PacketParser):
    def parse(self, data:bytes):
        iph = struct.unpack('!BBHHHBBH4s4s', data[:20])
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        tos = iph[1]
        total_length = iph[2]
        identification = iph[3]
        ttl = iph[5]
        protocol = iph[6]
        header_checksum = iph[7]
        source_ip = iph[8]
        dest_ip = iph[9]
        
        source_ip_str = '.'.join(map(str, source_ip))
        dest_ip_str = '.'.join(map(str, dest_ip))
        
        packet = InternetPacket()
        packet.set_version(version)
        packet.set_ihl(ihl)
        packet.set_tos(tos)
        packet.set_total_length(total_length)
        packet.set_identification(identification)
        packet.set_ttl(ttl)
        packet.set_protocol(protocol)
        packet.set_header_checksum(header_checksum)
        packet.set_source_ip(source_ip_str)
        packet.set_dest_ip(dest_ip_str)
        packet.set_payload(data[20:])

        return packet
