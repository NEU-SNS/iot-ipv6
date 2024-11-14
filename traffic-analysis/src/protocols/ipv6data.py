from src.helper import *
from src.helper.utils import *
import threading
logger = logging.getLogger('IoTv6')

class DataParser:
    # lock = threading.Lock()
    
    @staticmethod
    def isDataPacket(packet):
        return packet.haslayer('TCP') or packet.haslayer('UDP')

    @staticmethod
    def packet_parser(packet:Packet, device:str=None, table=None, version=6, addresses=List[str]):
        # assert DataParser.isDataPacket(packet) == True
        cur = table
        device = device
        src_mac, dst_mac, src_ip, dest_ip, _, device_mac = addresses
        #  
        
        protocol, size = None, None
        matter = 0
        if packet.haslayer('TCP'):
            protocol = 'TCP'
            size = len(packet['TCP'])
        elif packet.haslayer('UDP'):
            protocol = 'UDP'
            size = len(packet['UDP'])
            if packet['UDP'].dport == 5540 and packet['UDP'].sport == 5540:
                matter = 1
        # packet[2].mysummary() # Layer 4 summary. It gives the protocol of application layer for some packets
        
        flow = None
        flow_flag = 0
        if src_mac == device_mac:
            my_mac = src_mac
            flow = 'Outgoing'
        else:
            my_mac = dst_mac
            flow = 'Incoming'
            flow_flag = 1
            
        type = None
        type_flag = 0
        if (src_mac == utils.ROUTER_MAC or dst_mac == utils.ROUTER_MAC) and matter == 0:
            type = 'Global'
            type_flag = 1

        else:
            if matter == 1:
                type = 'Matter'
            else:
                type = 'Local'
        # with DataParser.lock: 
        if type_flag == 1:
            if flow_flag == 0:  # outgoing global
                if dest_ip.startswith(GLOBAL_IPV6_PREFIX):
                    return
                if dest_ip.startswith('fe80'):
                    return
                if dest_ip.startswith('fd'):
                    type = 'Local'
            else: 
                if src_ip.startswith(GLOBAL_IPV6_PREFIX):
                    return
                if src_ip.startswith('fe80'):
                    return
                if src_ip.startswith('fd'):
                    type = 'Local'
        setdb.insert_data(cur, my_mac, src_ip, dest_ip, flow, protocol, version, size, type)