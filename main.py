from lisniff import Sniffer
from lisniff import Packet
from lisniff import InternetPacket


sniffer = Sniffer()
logger = sniffer.get_logger()


@sniffer.on("packet_processed")
def packet_processed(packet:Packet): ...

@sniffer.on("ipv4_packet_processed")
def packet_processed(packet:InternetPacket):
    logger.info(f"{packet.get_dest_ip()} / {packet.get_source_ip()}")


sniffer.run()
