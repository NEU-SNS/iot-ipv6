from src.helper import *
from src.helper.utils import *
from scapy.all import DHCP6OptIAAddress
import threading
logger = logging.getLogger('IoTv6')

class DHCPv6Parser:
    # lock = threading.Lock()
    msgtype_dict = {
        'Solicit': 1,
        'Advertise': 2,
        'Request': 3,
        'Confirm': 4,
        'Renew': 5,
        'Rebind': 6,
        'Reply': 7,
        'Release': 8,
        'Decline': 9,
        'Reconfigure': 10,
        'Information-request': 11,
        'Relay-forward': 12,
        'Relay-reply': 13
    }
    dhcp6_cls_by_type = {1: "DHCP6_Solicit",
                     2: "DHCP6_Advertise",
                     3: "DHCP6_Request",
                     4: "DHCP6_Confirm",
                     5: "DHCP6_Renew",
                     6: "DHCP6_Rebind",
                     7: "DHCP6_Reply",
                     8: "DHCP6_Release",
                     9: "DHCP6_Decline",
                     10: "DHCP6_Reconf",
                     11: "DHCP6_InfoRequest",
                     12: "DHCP6_RelayForward",
                     13: "DHCP6_RelayReply"}
    duidtypes = {1: "Link-layer address plus time",
             2: "Vendor-assigned unique ID based on Enterprise Number",
             3: "Link-layer Address",
             4: "UUID"}
    
    """
    https://github.com/secdev/scapy/blob/master/scapy/layers/dhcp6.py
    """
    dhcp6opts = {1: "CLIENTID",
             2: "SERVERID",
             3: "IA_NA",
             4: "IA_TA",
             5: "IAADDR",
             6: "ORO",
             7: "PREFERENCE",
             8: "ELAPSED_TIME",
             9: "RELAY_MSG",
             11: "AUTH",
             12: "UNICAST",
             13: "STATUS_CODE",
             14: "RAPID_COMMIT",
             15: "USER_CLASS",
             16: "VENDOR_CLASS",
             17: "VENDOR_OPTS",
             18: "INTERFACE_ID",
             19: "RECONF_MSG",
             20: "RECONF_ACCEPT",
             21: "SIP Servers Domain Name List",  # RFC3319
             22: "SIP Servers IPv6 Address List",  # RFC3319
             23: "DNS Recursive Name Server Option",  # RFC3646
             24: "Domain Search List option",  # RFC3646
             25: "OPTION_IA_PD",  # RFC3633
             26: "OPTION_IAPREFIX",  # RFC3633
             27: "OPTION_NIS_SERVERS",  # RFC3898
             28: "OPTION_NISP_SERVERS",  # RFC3898
             29: "OPTION_NIS_DOMAIN_NAME",  # RFC3898
             30: "OPTION_NISP_DOMAIN_NAME",  # RFC3898
             31: "OPTION_SNTP_SERVERS",  # RFC4075
             32: "OPTION_INFORMATION_REFRESH_TIME",  # RFC4242
             33: "OPTION_BCMCS_SERVER_D",  # RFC4280
             34: "OPTION_BCMCS_SERVER_A",  # RFC4280
             36: "OPTION_GEOCONF_CIVIC",  # RFC-ietf-geopriv-dhcp-civil-09.txt
             37: "OPTION_REMOTE_ID",  # RFC4649
             38: "OPTION_SUBSCRIBER_ID",  # RFC4580
             39: "OPTION_CLIENT_FQDN",  # RFC4704
             40: "OPTION_PANA_AGENT",  # RFC5192
             41: "OPTION_NEW_POSIX_TIMEZONE",  # RFC4833
             42: "OPTION_NEW_TZDB_TIMEZONE",  # RFC4833
             48: "OPTION_LQ_CLIENT_LINK",  # RFC5007
             56: "OPTION_NTP_SERVER",  # RFC5908
             59: "OPT_BOOTFILE_URL",  # RFC5970
             60: "OPT_BOOTFILE_PARAM",  # RFC5970
             61: "OPTION_CLIENT_ARCH_TYPE",  # RFC5970
             62: "OPTION_NII",  # RFC5970
             65: "OPTION_ERP_LOCAL_DOMAIN_NAME",  # RFC6440
             66: "OPTION_RELAY_SUPPLIED_OPTIONS",  # RFC6422
             68: "OPTION_VSS",  # RFC6607
             79: "OPTION_CLIENT_LINKLAYER_ADDR",  # RFC6939
             82: "OPTION_SOL_MAX_RT",
             83: "OPTION_INF_MAX_RT",
             103: "OPTION_CAPTIVE_PORTAL",  # RFC8910
             112: "OPTION_MUD_URL",  # RFC8520
             }

    dhcp6opts_by_code = {1: "DHCP6OptClientId",
                     2: "DHCP6OptServerId",
                     3: "DHCP6OptIA_NA",
                     4: "DHCP6OptIA_TA",
                     5: "DHCP6OptIAAddress",
                     6: "DHCP6OptOptReq",
                     7: "DHCP6OptPref",
                     8: "DHCP6OptElapsedTime",
                     9: "DHCP6OptRelayMsg",
                     11: "DHCP6OptAuth",
                     12: "DHCP6OptServerUnicast",
                     13: "DHCP6OptStatusCode",
                     14: "DHCP6OptRapidCommit",
                     15: "DHCP6OptUserClass",
                     16: "DHCP6OptVendorClass",
                     17: "DHCP6OptVendorSpecificInfo",
                     18: "DHCP6OptIfaceId",
                     19: "DHCP6OptReconfMsg",
                     20: "DHCP6OptReconfAccept",
                     21: "DHCP6OptSIPDomains",  # RFC3319
                     22: "DHCP6OptSIPServers",  # RFC3319
                     23: "DHCP6OptDNSServers",  # RFC3646
                     24: "DHCP6OptDNSDomains",  # RFC3646
                     25: "DHCP6OptIA_PD",  # RFC3633
                     26: "DHCP6OptIAPrefix",  # RFC3633
                     27: "DHCP6OptNISServers",  # RFC3898
                     28: "DHCP6OptNISPServers",  # RFC3898
                     29: "DHCP6OptNISDomain",  # RFC3898
                     30: "DHCP6OptNISPDomain",  # RFC3898
                     31: "DHCP6OptSNTPServers",  # RFC4075
                     32: "DHCP6OptInfoRefreshTime",  # RFC4242
                     33: "DHCP6OptBCMCSDomains",  # RFC4280
                     34: "DHCP6OptBCMCSServers",  # RFC4280
                     # 36: "DHCP6OptGeoConf",            #RFC-ietf-geopriv-dhcp-civil-09.txt  # noqa: E501
                     37: "DHCP6OptRemoteID",  # RFC4649
                     38: "DHCP6OptSubscriberID",  # RFC4580
                     39: "DHCP6OptClientFQDN",  # RFC4704
                     40: "DHCP6OptPanaAuthAgent",  # RFC-ietf-dhc-paa-option-05.txt  # noqa: E501
                     41: "DHCP6OptNewPOSIXTimeZone",  # RFC4833
                     42: "DHCP6OptNewTZDBTimeZone",  # RFC4833
                     43: "DHCP6OptRelayAgentERO",  # RFC4994
                     # 44: "DHCP6OptLQQuery",            #RFC5007
                     # 45: "DHCP6OptLQClientData",       #RFC5007
                     # 46: "DHCP6OptLQClientTime",       #RFC5007
                     # 47: "DHCP6OptLQRelayData",        #RFC5007
                     48: "DHCP6OptLQClientLink",  # RFC5007
                     56: "DHCP6OptNTPServer",  # RFC5908
                     59: "DHCP6OptBootFileUrl",  # RFC5790
                     60: "DHCP6OptBootFileParam",  # RFC5970
                     61: "DHCP6OptClientArchType",  # RFC5970
                     62: "DHCP6OptClientNetworkInterId",  # RFC5970
                     65: "DHCP6OptERPDomain",  # RFC6440
                     66: "DHCP6OptRelaySuppliedOpt",  # RFC6422
                     68: "DHCP6OptVSS",  # RFC6607
                     79: "DHCP6OptClientLinkLayerAddr",  # RFC6939
                     103: "DHCP6OptCaptivePortal",  # RFC8910
                     112: "DHCP6OptMudUrl",  # RFC8520
                     }

    @staticmethod
    def extract_duid(packet):
        # if packet.haslayer("DUID_LL"):
        #     return f"DUID_LL {packet['DUID_LL'].lladdr}"
        # elif packet.haslayer("DUID_LLT"):
        #     return f"DUID_LLT {packet['DUID_LLT'].timeval} {packet['DUID_LLT'].lladdr}"
        # elif packet.haslayer("DUID_UUID"):
        #     return f"DUID_UUID {packet['DUID_UUID'].uuid}"
        # elif packet.haslayer("DUID_EN"):
        #     return f"DUID_EN {packet['DUID_EN'].id}"
        if packet.haslayer('DUID_EN'):
            num = packet['DUID_EN'].enterprisenum 
            if num == 43793:
                return "systemd"
            return f"PEN-{num}"
        return None

    @staticmethod
    def isDHCPv6(packet):
        return packet.haslayer(scapy.all.IPv6) and packet.haslayer('UDP') and \
            ((packet['UDP'].sport==546 and packet['UDP'].dport==547) or (packet['UDP'].sport==547 and packet['UDP'].dport==546))
    
    @staticmethod
    def isDHCPSolicit(packet):
        """
        Message Type 1
        """
        return packet.haslayer('DHCP6_Solicit')
    
    @staticmethod
    def isDHCPAdvertisement(packet):
        """
        Message Type 2
        """
        return packet.haslayer('DHCP6_Advertise')
    
    @staticmethod
    def isDHCPRequest(packet):
        """
        Message Type 3
        """
        return packet.haslayer('DHCP6_Request')
    
    @staticmethod
    def isDHCPReply(packet):
        """
        Message Type 7
        """
        return packet.haslayer('DHCP6_Reply')
    
    @staticmethod
    def isDHCPInfoRequest(packet):
        """
        Message Type 11
        """
        return packet.haslayer('DHCP6_InfoRequest')
    
    @staticmethod
    def get_dhcpv6_options(packet):
        options = []
        for i in range(len(packet.layers())-4):
            name = packet.getlayer(i+4).name
            options.append(name)
        return options
    
    @staticmethod
    def get_dhcpv6_req_options(packet):
        req_options = []
        if packet.haslayer('DHCP6OptOptReq'):
            opts = packet['DHCP6OptOptReq'].reqopts
            req_options = [str(o) for o in opts]
            # for option in opts:
                # if option in DHCPv6Parser.dhcp6opts:
                #     req_options.append(DHCPv6Parser.dhcp6opts[option])
                # else:
                #     req_options.append(f"Unknown-{option}")
                #     logger.debug(f"Unknown DHCPv6 Request Option {option}")
        return req_options
    
    @staticmethod
    def parseDHCPSolicit(packet):
        tsn_id = hex(packet['DHCP6_Solicit'].trid)
        if packet.haslayer('DHCP6OptClientId'):
            client_duid = DHCPv6Parser.extract_duid(packet)
        else:
            client_duid = None
        options, req_options =  None, None
        if len(packet['DHCP6_Solicit'].payload) > 0:    
            options = DHCPv6Parser.get_dhcpv6_options(packet)
            if packet.haslayer('DHCP6OptOptReq'):
                req_options = DHCPv6Parser.get_dhcpv6_req_options(packet)
        return tsn_id, client_duid, options, req_options
    
    @staticmethod
    def parseDHCPAdvertisement(packet):
        # tsn_id = hex(packet['DHCP6_Advertise'].trid)
        tsn_id = None
        if packet.haslayer('DHCP6OptClientId'):
            server_duid = DHCPv6Parser.extract_duid(packet)
        else:
            server_duid = None
        options = None
        if len(packet['DHCP6_Advertise'].payload) > 0:    
            options = DHCPv6Parser.get_dhcpv6_options(packet)
        return tsn_id, server_duid, options
    
    @staticmethod
    def parseDHCPRequest(packet):
        # tsn_id = hex(packet['DHCP6_Request'].trid)
        tsn_id = None
        if packet.haslayer('DHCP6OptClientId'):
            client_duid = DHCPv6Parser.extract_duid(packet)
        else:
            client_duid = None
        options, req_options =  None, None
        if len(packet['DHCP6_Request'].payload) > 0:    
            options = DHCPv6Parser.get_dhcpv6_options(packet)
            if packet.haslayer('DHCP6OptOptReq'):
                req_options = DHCPv6Parser.get_dhcpv6_req_options(packet)
        return tsn_id, client_duid, options, req_options
    
    @staticmethod
    def parseDHCPReply(packet):
        # tsn_id = hex(packet['DHCP6_Reply'].trid)
        tsn_id = None
        server_duid = None
        # server_duid = DHCPv6Parser.extract_duid(packet)
        
        dns_svr_list = []
        iana_ips = []
        iata_ips = []

        if packet.haslayer('DHCP6OptIA_NA') and packet['DHCP6OptIA_NA'].optcode == 3:
            iana_options = packet['DHCP6OptIA_NA'].ianaopts
            iana_ips = [x.addr for x in iana_options if isinstance(x, DHCP6OptIAAddress)]

        if packet.haslayer('DHCP6OptIA_TA') and packet['DHCP6OptIA_TA'].optcode == 4:
            iata_options = packet['DHCP6OptIA_TA'].iataopts
            iata_ips = [x.addr for x in iata_options if isinstance(x, DHCP6OptIAAddress)]

        # if packet.haslayer('DHCP6OptDNSServers') and packet['DHCP6OptDNSServers'].optcode == 23:
        #     dns_svr_list = packet['DHCP6OptDNSServers'].dnsservers

        # if len(dns_svr_list) == 0:
            # dns_svr_list.append(None)
        options = None
        # if len(packet['DHCP6_Reply'].payload) > 0:
        #     options = DHCPv6Parser.get_dhcpv6_options(packet)
        
        return tsn_id, server_duid, dns_svr_list, iana_ips, iata_ips, options
    
    @staticmethod
    def parseDHCPInfoRequest(packet):
        tsn_id = hex(packet['DHCP6_InfoRequest'].trid)
        if packet.haslayer('DHCP6OptClientId'):
            client_duid = DHCPv6Parser.extract_duid(packet)
        else:
            client_duid = None
        options, req_options =  None, None
        if len(packet['DHCP6_InfoRequest'].payload) > 0:    
            options = DHCPv6Parser.get_dhcpv6_options(packet)
            if packet.haslayer('DHCP6OptOptReq'):
                req_options = DHCPv6Parser.get_dhcpv6_req_options(packet)
        return tsn_id, client_duid, options, req_options
        
    @staticmethod
    def packet_parser(packet:Packet, device:str=None, table=None, addresses=List[str]):
        # assert ICMPv6Parser.isDHCPv6(packet) == True
        cur = table
        device = device
        src_mac, _, src_ip, dest_ip, _ = addresses
        msgtype = packet['UDP'].msgtype
        if msgtype not in DHCPv6Parser.msgtype_dict.values():
            logger.error('Invalid DHCPv6 Packet')
            # raise Exception("Invalid DHCPv6 Packet")
        match msgtype:
            case 1:
                # if DHCPv6Parser.isDHCPSolicit(packet):
                tsn_id, client_duid, options, req_options = DHCPv6Parser.parseDHCPSolicit(packet)

                setdb.insert_dhcp_solicit(cur, src_mac, src_ip, dest_ip, tsn_id, client_duid, options, req_options)
                    
            case 2:
                # if DHCPv6Parser.isDHCPAdvertisement(packet):
                tsn_id, server_duid, options = DHCPv6Parser.parseDHCPAdvertisement(packet)

                setdb.insert_dhcp_advertisememts(cur, src_mac, src_ip, dest_ip, tsn_id, server_duid, None, None, None)
            case 3:
                # if DHCPv6Parser.isDHCPRequest(packet):
                tsn_id, client_duid, options, req_options = DHCPv6Parser.parseDHCPRequest(packet)

                setdb.insert_dhcp_request(cur, src_mac, src_ip, dest_ip, tsn_id, None, None, options, req_options)
            case 7:
                # if DHCPv6Parser.isDHCPReply(packet):
                tsn_id, server_duid, _, iana_ips, iata_ips, options = DHCPv6Parser.parseDHCPReply(packet)

                
                setdb.insert_dhcp_reply(cur, src_mac, iana_ips, iata_ips, tsn_id, src_ip, dest_ip, options)
            case 11:
                # if DHCPv6Parser.isDHCPInfoRequest(packet):
                tsn_id, client_duid, options, req_options = DHCPv6Parser.parseDHCPInfoRequest(packet)

                setdb.insert_dhcp_info_request(cur, src_mac, src_ip, dest_ip, tsn_id, client_duid, options, req_options)
            case 5:
                # FIXME Renew
                pass
            case 4:
                # FIXME Confirm
                pass
            case _:
                try:
                    type = DHCPv6Parser.dhcp6_cls_by_type[packet['UDP'].msgtype]
                    logger.debug(f'Unknown DHCPv6 message type {type} received.')
                except:
                    logger.error(f'Unknown DHCPv6 message type None received.')
            
        return 