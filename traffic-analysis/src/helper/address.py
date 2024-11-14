from src.helper.utils import *
logger = logging.getLogger('IoTv6')

DNS_ADDRESS = ['8.8.8.8', '8.8.4.4', '155.33.33.70', '155.33.33.75']
LOCAL_IPS = ['129.10.227.248', '129.10.227.207']
LOCAL_MACS = ['22:ef:03:1a:97:b9']

# def is_eui64_ipv6(mac_address, ipv6_address):
#     ipv6_interface_identifier = ipv6_address.split(':')[-8:]
#     ipv6_interface_identifier = [re.sub("^0+", "", octet) for octet in ipv6_interface_identifier]
#     ipv6_interface_identifier_str = ":".join(ipv6_interface_identifier)
#     eui64_mac_address = mac_address[:8] + 'ff:fe' + mac_address[8:]
#     return ipv6_interface_identifier_str == eui64_mac_address[9:]

def validate_ip_address(address):
    try:
        ip = ipaddress.ip_address(address)
        # print("IP address {} is valid. The object returned is {}".format(address, ip))
        return True
    except ValueError:
        # print("IP address {} is not valid".format(address)) 
        return False
    
def get_ip_type(address:str) -> None:
    try:
        ip = ipaddress.ip_address(address)

        if isinstance(ip, ipaddress.IPv4Address):
            print(f"{address} is an IPv4 address")
        elif isinstance(ip, ipaddress.IPv6Address):
            print(f"{address} is an IPv6 address")
    except ValueError:
        print(f"{address} is an invalid IP address")
        
def is_ipv6(address:str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv6Address):
            # print("{} is an IPv6 address".format(address))
            return True
        else:
            return False
    except ValueError:
        return False
    
def is_ipv4(address:str) -> bool:
    try:
        ip = ipaddress.ip_address(address)
        if isinstance(ip, ipaddress.IPv4Address):
            # print("{} is an IPv4 address".format(address))
            return True
        else:
            return False
    except ValueError:
        return False
    
def check_ipv6_same(ip1, ip2):
    """
    Checks if 2 IPV6 addresses are the same returns true if same 
    """
    return ipaddress.IPv6Address(ip1) == ipaddress.IPv6Address(ip2)


def check_ipv6_multicast_addr(ip):
    """
    Checks if provided ipv6 address is multicast address or not
    """
    return ipaddress.IPv6Address(ip).is_multicast

def address_configuration_method_text(m, o, a):
    if m == 1 and a == 0:
        return 'Stateful_DHCPv6'
    elif o == 0 and m == 0 and a == 1:
        return "SLAAC"
    elif o == 1 and m == 0 and a == 1:
        return 'Stateless_DHCPv6'
    else: 
        return "Unknown"
    
def address_configuration_method(m, o, a):
        """Config based on Router Advertisement flags

        Args:
            m (binary): M-Flag
            o (binary): O-Flag
            a (binary): A-Flag

        Returns:
            binary: if each config is enabled
        """
        slaac_enabled = 0
        stateless_DHCPv6_enabled = 0
        stateful_DHCPv6_enabled = 0
        if m == 1:
            stateful_DHCPv6_enabled = 1
        if a == 1:
            slaac_enabled = 1
        if o == 1:
            stateless_DHCPv6_enabled = 1
            
        return slaac_enabled, stateless_DHCPv6_enabled, stateful_DHCPv6_enabled

def get_ipv6_type(address:str) -> str:
    try:
        if not is_ipv6(address):
            return 1
        
        if check_ipv6_link_local_addr(address):
            return 'LinkLocal'
        elif check_ipv6_global_unicast(address): 
            return 'GlobalUnicast'
        elif check_ipv6_unique_local(address):
            return 'UniqueLocal'
        elif check_ipv6_unspecified(address):
            return "Unspecified"
        else:
            # logger.error(f"{address} is an unknown invalid IPv6 address")
            return "Unknown"
        
    except ValueError:
        logger.error(f"{address} is an invalid IP address")

def get_ipv6_type_binary(address:str) -> int:
    try:
        if not is_ipv6(address):
            return 2
        
        if check_ipv6_link_local_addr(address):
            return 1
        elif check_ipv6_global_unicast(address): 
            return 0
        elif check_ipv6_unique_local(address):
            return 1
        elif check_ipv6_unspecified(address):
            return 1
        else:
            # logger.error(f"{address} is an unknown invalid IPv6 address")
            return 2
        
    except ValueError:
        logger.error(f"{address} is an invalid IP address")

def check_ipv6_link_local_addr(ip):
    """
    Checks if provided ipv6 address is link local address or not
    """
    return ipaddress.IPv6Address(ip).is_link_local

def check_ipv6_global_unicast(ip):
    """
    Checks if provided ipv6 address is global address and unicast address 
    """
    ip_obj = ipaddress.IPv6Address(ip)
    return ip_obj.is_global and not ip_obj.is_multicast

def check_ipv6_unique_local(ip):
    """
    Check if ipv6 address is uniqle local
    """
    ip_obj = ipaddress.IPv6Address(ip)
    return ip_obj.is_private and check_in_network("fc00::/7", ip)

def check_ipv6_unspecified(ip):
    """
    Checks if provided ipv6 address is unspecified "::"
    """
    return ipaddress.IPv6Address(ip).is_unspecified or ip == "::" or ip == "::1"

def check_in_network(network_prefix, ip):
    if ip is None or network_prefix is None:
        return False
    network = ipaddress.IPv6Network(network_prefix, strict=False)
    address = ipaddress.IPv6Address(ip)
    return address in network

def is_eui64_address(mac_address, ipv6_address):
    eui_64_lla = get_link_EUI64_local_address(mac_address)
    eui_64_lla = ':'.join(eui_64_lla.split(':')[-4:])
    ipv6_address = ':'.join(ipv6_address.split(':')[-4:])
    return ipv6_address == eui_64_lla

def get_link_EUI64_local_address(mac:str) -> str:
    """
    Method obtains link local address from a devices MAC address based on RFC 4291
    using EUI64
    """
    octets = expand_mac_address(mac).split(":")
    octets.insert(3, "ff")
    octets.insert(4, "fe")
    first_octet_str = format(int(octets[0], 16), 'b').zfill(8)
    first_octet_list = list(first_octet_str)
    first_octet_list[6] = "1" if first_octet_list[6] == "0" else "0"
    octets[0] = format(int("".join(first_octet_list), 2), '02x')
    
    doublets = []
    for i in range(0, len(octets), 2):
        doublets.append(octets[i]+octets[i+1])
    link_local_addr = "fe80::"+ (":".join(doublets))
    
    return link_local_addr

def is_mac_addr_all_nodes_multicast(mac):
    """
    The ipv6 address "ff02::1 is allnodes multicast address it corresponds to 
    Layer 2 mac address 33-33-00-00-00-01 

    Check for more info: https://en.wikipedia.org/wiki/Multicast_address#Ethernet
    """
    return mac is not None and mac.startswith("33") and mac.endswith("1")


### Old ones
def addressing_method(address:str) -> str:
    """Determine traffic addressing method: unicast, multicast, broadcast

    Args:
        address (str): destination MAC address

    Returns:
        str: addressing method
    """

    if is_broadcast(address):
        return 2
    elif is_multicast(address):
        return 1
    # elif is_ipv6(address) and is_anycast(address):
    #     return 'anycast' 
    return 0

def is_broadcast(address:str) -> bool:
    return address=='ff:ff:ff:ff:ff:ff'


def is_multicast(address:str) -> bool:
    # if utils.validate_ip_address(address): 
    #     return ipaddress.ip_address("127.0.0.1").is_multicast
    return (address.startswith('01:00:5e') or address.startswith('33:33'))

def is_local(ip_src, ip_dst):
    is_local = False
    try:
        is_local = (ipaddress.ip_address(ip_src).is_private and ipaddress.ip_address(ip_dst).is_private
                ) or (ipaddress.ip_address(ip_src).is_private and (ip_dst in LOCAL_IPS) 
                ) or (ipaddress.ip_address(ip_dst).is_private and (ip_src in LOCAL_IPS)) # =="129.10.227.248" or ip_dst=="129.10.227.207"
    except:
        # print('Error:', ip_src, ip_dst)
        return 1
    return is_local