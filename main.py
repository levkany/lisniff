from lisniff import Sniffer
from lisniff import Packet


sniffer = Sniffer()
logger = sniffer.get_logger()


@sniffer.on("packet_processed")
def packet_processed(packet:Packet):
    logger.info(type(packet))


sniffer.run()
