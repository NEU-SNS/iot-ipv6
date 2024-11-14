from src.helper import *
from src.helper.utils import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
logger = logging.getLogger('IoTv6')

class DNSParser:
    # https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
    dnstypes = {
        0: "ANY",
        1: "A", 2: "NS", 3: "MD", 4: "MF", 5: "CNAME", 6: "SOA", 7: "MB", 8: "MG",
        9: "MR", 10: "NULL", 11: "WKS", 12: "PTR", 13: "HINFO", 14: "MINFO",
        15: "MX", 16: "TXT", 17: "RP", 18: "AFSDB", 19: "X25", 20: "ISDN",
        21: "RT", 22: "NSAP", 23: "NSAP-PTR", 24: "SIG", 25: "KEY", 26: "PX",
        27: "GPOS", 28: "AAAA", 29: "LOC", 30: "NXT", 31: "EID", 32: "NIMLOC",
        33: "SRV", 34: "ATMA", 35: "NAPTR", 36: "KX", 37: "CERT", 38: "A6",
        39: "DNAME", 40: "SINK", 41: "OPT", 42: "APL", 43: "DS", 44: "SSHFP",
        45: "IPSECKEY", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 49: "DHCID",
        50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA", 53: "SMIMEA", 55: "HIP",
        56: "NINFO", 57: "RKEY", 58: "TALINK", 59: "CDS", 60: "CDNSKEY",
        61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD", 64: "SVCB", 65: "HTTPS",
        99: "SPF", 100: "UINFO", 101: "UID", 102: "GID", 103: "UNSPEC", 104: "NID",
        105: "L32", 106: "L64", 107: "LP", 108: "EUI48", 109: "EUI64", 249: "TKEY",
        250: "TSIG", 256: "URI", 257: "CAA", 258: "AVC", 259: "DOA",
        260: "AMTRELAY", 32768: "TA", 32769: "DLV", 65535: "RESERVED"
    }
    query_types = dnstypes
    answer_types = dnstypes
    response_codes = {
        0: "No Error (NOERROR)",
        1: "Format Error (FORMERR)",
        2: "Server Failure (SERVFAIL)",
        3: "Non-Existent Domain (NXDOMAIN)",
        4: "Not Implemented (NOTIMP)",
        5: "Query Refused (REFUSED)",
        6: "Name Exists when it should not (YXDOMAIN)",
        7: "RR Set Exists when it should not (YXRRSET)",
        8: "RR Set that should exist does not (NXRRSET)",
        9: "Not Authorized (NOTAUTH)",
        10: "Name not in zone (NOTZONE)",
        11: "Requested record not found (NODATA)"
    }
    
    @staticmethod
    def isDNS(packet):
        return packet.haslayer('DNS') 
    
    @staticmethod
    def is_mDNS(dst_mac, sport, dport):
        return (sport == 5353 or dport == 5353) # dst_mac == "33:33:00:00:00:fb" or 
    
    @staticmethod
    def isDNSRequest(packet):
        return packet.haslayer('DNS') and packet['DNS'].qr == 0 
    
    @staticmethod
    def isDNSResponse(packet):
        return packet.haslayer('DNS') and packet['DNS'].qr == 1
    
    def parse_request(packet):
        query_count = packet['DNS'].qdcount
        queries = []
        
        if query_count > 0:
            for query in packet['DNS'].qd:
                qtype = DNSParser.query_types.get(query.qtype, "Unknown")
                try:
                    qname = query.qname.decode("utf-8") 
                except:
                    qname = query.qname
                queries.append((qtype, qname))

        tsn_id = hex(packet['DNS'].id)
        
        if len(queries) == 0:
            queries.append((None, None))
        
        # for query in queries:
        #     qtype, qname = query
            # insert_dns_request(cur, mac, qname, qtype, dest_ip, tsn_id, version)
        return queries, tsn_id
    
    def parse_response(packet):
        # version, src_ip, dest_ip = None, None, None 
        qdcount = packet['DNS'].qdcount
        qnames = [packet['DNS'].qd[i].qname.decode('utf-8') for i in range(qdcount)]
        rcode = packet['DNS'].rcode
        qtypes = [packet['DNS'].qd[i].qtype for i in range(qdcount)]

        # if packet.haslayer('IP'):
        #     src_ip, dest_ip = packet['IP'].src, packet['IP'].dst
        #     version = 4
        # elif packet.haslayer('IPv6'):
        #     src_ip, dest_ip = packet['IPv6'].src, packet['IPv6'].dst
        #     version = 6
        answer_count = packet['DNS'].ancount 
        tsn_id = hex(packet['DNS'].id)
        answers = []

        if answer_count > 0:
            for i in range(answer_count):
                ans = packet['DNS'].an[i]
                aname = ans.rrname.decode('utf-8')
                atype = ans.type
                try:
                    if ans.type == 65:
                        adata = None
                    else:
                        adata = (
                            ans.rdata.decode('utf-8') if ans.type == 5 and hasattr(ans, 'rdata') else   # cname 
                            str(ans.rdata) if hasattr(ans, 'rdata') else
                            None
                        )
                        adata = adata.decode('utf-8') if isinstance(adata, bytes) else adata
                except:
                    adata = None
                answers.append((aname, atype, adata))
        
        ns_count = packet['DNS'].nscount
        if ns_count > 0:
            for i in range(ns_count):
                ans = packet['DNS'].ns[i]
                aname = ans.rrname.decode('utf-8')
                atype = ans.type
                adata = (
                    str(ans.mname.decode('utf-8')) if hasattr(ans, 'mname') else None
                )
                answers.append((aname, atype, adata))
        ar_count = packet['DNS'].arcount
        if ar_count > 0:
            for i in range(ar_count):
                ans = packet['DNS'].ar[i]
                aname = ans.rrname.decode('utf-8') if hasattr(ans, 'rrname') else None
                atype = ans.type if hasattr(ans, 'type') else None
                adata = (
                    str(ans.rdata) if hasattr(ans, 'rdata') else None
                )
                answers.append((aname, atype, adata))
        atypes = [ans[1] for ans in answers]
        
        if rcode == 0 and ( answer_count == 0 or  all(qtype != atype for qtype in qtypes for atype in atypes) ):
            if 28 in qtypes:    # AAAA
                status = 12
            status = 13 # DNSParser.response_codes.get(11)
        else:
        #     status = DNSParser.response_codes.get(packet['DNS'].rcode, None)
            status = rcode
        if len(answers) == 0:
            answers.append((None, None, None))
        
        # for ans in answers:
        #     for i, qname in enumerate(qnames):
        #         aname, atype, adata = ans 
                # insert_dns_response(cur, mac, qname, aname, answer_types.get(atype, "Unknown"), adata, tsn_id, status, version)  
        return answers, qnames, qtypes, tsn_id, status
    
    @staticmethod
    def packet_parser(packet, device:str=None, table=None, addresses=List[str]):
        # assert DNSParser.isDNS(packet) == True
        cur = table
        device = device
        src_mac, dst_mac, src_ip, dest_ip, _, sport, dport= addresses
        version = None
        if packet.haslayer('IP'):
            version = 4
        elif packet.haslayer('IPv6'):
            version = 6
        
        mDNS = DNSParser.is_mDNS(dst_mac, sport, dport)
        
        if DNSParser.isDNSRequest(packet):
            queries, tsn_id = DNSParser.parse_request(packet) 
            if not mDNS:
                for q in queries:
                    qtype, qname = q
                    setdb.insert_dns_request(cur, src_mac, qname, qtype, src_ip, tsn_id, version)
            else:
                if version == 4:
                    return
                for q in queries:
                    qtype, qname = q
                    setdb.insert_mdns_request(cur, src_mac, qname, qtype, dest_ip, tsn_id, version)
        elif DNSParser.isDNSResponse(packet):
            
            answers, qnames, qtypes, tsn_id, status = DNSParser.parse_response(packet) 
            if not mDNS:
                for ans in answers:
                    for i, qname in enumerate(qnames):
                        qtype = qtypes[i]
                        aname, atype, adata = ans 
                        setdb.insert_dns_response(cur, dst_mac, qname, aname, DNSParser.answer_types.get(atype, str(atype)), adata, tsn_id, status, version)  
            else:
                if version == 4:
                    return
                for ans in answers:
                    # for i, qname in enumerate(qnames):
                    #     qtype = qtypes[i]
                    aname, atype, adata = ans 
                    # logger.debug(f'MDNS: {src_mac=} {qname=} {aname=} {atype=} {adata=} {tsn_id=} {status=}')
                    setdb.insert_mdns_response(cur, dst_mac, None, aname, DNSParser.answer_types.get(atype, str(atype)), adata, tsn_id, status, version)  
            # logger.debug(f"DNS Response {packet.summary()}")
            
        