from src.helper import *
from src.helper.utils import *
from src.helper.address import address_configuration_method
from scapy.all import ICMPv6ND_RA, ICMPv6NDOptRDNSS
from scapy.layers.inet6 import ICMPv6Unknown
logger = logging.getLogger('IoTv6')

class ICMPv6Parser:
    """NDP defines five ICMPv6 packet types for the purpose of router solicitation, router advertisement, neighbor solicitation, neighbor advertisement, and network redirects
    
    Router Solicitation (Type 133)
        Hosts inquire with Router Solicitation messages to locate routers on an attached link. Routers which forward packets not addressed to them generate Router Advertisements immediately upon receipt of this message rather than at their next scheduled time.
    Router Advertisement (Type 134)
        Routers advertise their presence together with various link and Internet parameters either periodically, or in response to a Router Solicitation message.
    Neighbor Solicitation (Type 135)
        Neighbor solicitations are used by nodes to determine the link-layer address of a neighbor, or to verify that a neighbor is still reachable via a cached link-layer address.
    Neighbor Advertisement (Type 136)
        Neighbor advertisements are used by nodes to respond to a Neighbor Solicitation message, or unsolicited to provide new information quickly.
    Redirect (Type 137)
        Routers may inform hosts of a better first-hop router for a destination.
    
    """
    
    mac_dict = {}
    
    @staticmethod
    def get_mac_dict(in_dic):
        mac_dict = in_dic
        # print(mac_dict)
        return 0
    
    @staticmethod
    def isICMPv6(packet):
        return packet.haslayer(scapy.all.IPv6) and packet[scapy.all.IPv6].nh==58
    
    @staticmethod
    def isRouterSolicitation(packet):
        return packet.haslayer('ICMPv6ND_RS') and packet['ICMPv6ND_RS'].type == 133
    
    @staticmethod
    def isRouterAdvertisement(packet):
        return packet.haslayer('ICMPv6ND_RA') and packet['ICMPv6ND_RA'].type == 134
    
    @staticmethod
    def isNeighborSolicitation(packet):
        return packet.haslayer('ICMPv6ND_NS') and packet['ICMPv6ND_NS'].type == 135 
        
    @staticmethod
    def isNeighborAdvertisement(packet):
        return packet.haslayer('ICMPv6ND_NA') and \
            packet['ICMPv6ND_NA'].type == 136

            # packet['ICMPv6ND_NA'].S == 0 and \
            # packet['ICMPv6ND_NA'].R == 0 and \
            # packet['IPv6'].dst == "ff02::1"
    
    
    @staticmethod
    def isRDNSS(packet):
        return packet.haslayer(ICMPv6ND_RA) and packet.haslayer(ICMPv6NDOptRDNSS)

    @staticmethod
    def get_RDNSS_address(packet):
        rdnss_addresses = []
        if ICMPv6Parser.isRDNSS(packet):
            rdnss_addresses = packet[ICMPv6NDOptRDNSS].dns
        return rdnss_addresses
    
    @staticmethod
    def get_icmpv6nd_options(packet):
        options = []
        for layer in packet.layers():
            layer_name = layer.__name__
            if 'ICMPv6NDOpt' in layer_name:
                options.append(layer_name)
        return options
    
    @staticmethod
    def get_icmpv6nd_payload(packet):
        options = {}
        for i in range(len(packet.layers())):
            name = packet.getlayer(i).name
            if 'ICMPv6 Neighbor Discovery Option' in name:
                payload = str(packet.getlayer(i-1).payload)
                options[name.split('ICMPv6 Neighbor Discovery Option')[1]] = payload
        return options
    
    @staticmethod
    def get_icmpv6nd_fields(packet):
        fields = packet[2].fields
        return fields
    
    @staticmethod
    def get_icmpv6nd_option_fields(packet):
        options = {}
        for i in range(len(packet.layers())):
            name = packet.getlayer(i).name
            if 'ICMPv6 Neighbor Discovery Option' in name:
                field = packet.getlayer(i).fields
                options = {name.split('ICMPv6 Neighbor Discovery Option')[1]:field}
        return options
    
    @staticmethod
    def parseRouterSolicitation(packet, device:str=None, cur=None):
        """Hosts inquire with Router Solicitation messages to locate routers on an attached link. No other use.
        """
        return 0
    
    @staticmethod
    def parseRouterAdvertisement(packet, device:str=None, cur=None):
        m = packet['ICMPv6ND_RA'].M
        o = packet['ICMPv6ND_RA'].O
        a, prefix = None, None
        if  packet.haslayer('ICMPv6NDOptPrefixInfo') and packet['ICMPv6NDOptPrefixInfo'].type == 3: 
            a = packet['ICMPv6NDOptPrefixInfo'].A
            prefix = packet['ICMPv6NDOptPrefixInfo'].prefix
            prefix_length = packet['ICMPv6NDOptPrefixInfo'].prefixlen
            prefix = f"{prefix}/{prefix_length}"

        dns_servers = []
        if ICMPv6Parser.isRDNSS(packet):
            dns_servers = ICMPv6Parser.get_RDNSS_address(packet)
        if len(dns_servers) == 0:
            dns_servers.append(None)
        
        
        return m, o, a, prefix, dns_servers
    
    
    
    @staticmethod
    def parseNeighborSolicitation(packet, device:str=None, cur=None):
        """
        1. Determine the link-layer address of a neighbor 2. Duplicate Address Detection
        """
        target = packet['ICMPv6ND_NS'].tgt
        return target
    
    @staticmethod
    def parseNeighborAdvertisement(packet, device:str=None, cur=None):
        """
        Neighbor advertisements are used by nodes to respond to a Neighbor Solicitation message. 1. IP to MAC translation 2. Duplicate Address Detection
        """
        target = packet['ICMPv6ND_NA'].tgt
        if packet['ICMPv6ND_NA'].S == 0 and \
            packet['ICMPv6ND_NA'].R == 0 and \
            packet['IPv6'].dst == "ff02::1":
            pass
        else:   # TODO
            s_flag = packet['ICMPv6ND_NA'].S    # When set, the S-bit indicates that the advertisement was sent in response to a Neighbor Solicitation from the Destination address.
            r_flag = packet['ICMPv6ND_NA'].R    # router flag = 1 -> sender is the router
            o_flag = packet['ICMPv6ND_NA'].O    # Override flag.  When set, the O-bit indicates that the advertisement should override an existing cache entry and update the cached link-layer address.
            # TODO S=0 R=1 O=1 used by Apple homepod to update the cache
            dest_ip = packet['IPv6'].dst 
            if s_flag == 0:
                pass
                # logger.debug(f'Neighbor Advertisement message {s_flag=} {r_flag=} {o_flag=} {dest_ip=} | {str(packet)}')
        
        return target

    @staticmethod
    def packet_parser(packet:Packet, device:str=None, table=None, addresses=List[str]):
        cur = table
        device = device
        src_mac, _, src_ip, dest_ip, _ = addresses
        # assert ICMPv6Parser.isICMPv6(packet) == True
        # if packet[scapy.all.IPv6].type not in [133, 134, 135, 136, 137]:
            # logger.info(f'Unknown ICMPv6 Packet Type: {packet[scapy.all.IPv6].type}')
            # pass
        if ICMPv6Parser.isRouterSolicitation(packet):
            # ICMPv6Parser.parseRouterSolicitation(packet)
            setdb.insert_rs(cur, src_mac, src_ip, dest_ip)
        elif ICMPv6Parser.isRouterAdvertisement(packet):
            m, o, a, prefix, dns_servers = ICMPv6Parser.parseRouterAdvertisement(packet)
            setdb.insert_ra(cur, src_mac, m, o, a, prefix, dns_servers, src_ip, dest_ip)
        elif ICMPv6Parser.isNeighborSolicitation(packet):
            target = ICMPv6Parser.parseNeighborSolicitation(packet)
            setdb.insert_ns(cur, src_mac, target, src_ip, dest_ip, 0)
        elif ICMPv6Parser.isNeighborAdvertisement(packet):
            target = ICMPv6Parser.parseNeighborAdvertisement(packet)
            setdb.insert_na(cur, src_mac, src_ip, dest_ip, target)
        elif packet.haslayer('ICMPv6ND_Redirect'):
            # TODO add support for redirect
            # logger.debug(f'{device}: NDP Type 137 Redirect {src_ip} -> {dest_ip}')
            """
            Routers send Redirect packets to inform a host of a better first-hop
            node on the path to a destination.  Hosts can be redirected to a
            better first-hop router but can also be informed by a redirect that
            the destination is in fact a neighbor.  The latter is accomplished by
            setting the ICMP Target Address equal to the ICMP Destination
            Address.
            """
            # TODO our old Samsung fridge use redirect to ask Apple homepod to use its fd56 and global ips instead of fe80 ones
            # FIXME APPLE Homepod uses unicast router advertisement for its own routing, with M-Flag set. Advertising fdc0 ULA
        else:
            logger.error(f'{device}: Unknown ICMPv6 NDP Packet')
            # raise Exception("Unknown ICMPv6 Packet")
            return
    
    