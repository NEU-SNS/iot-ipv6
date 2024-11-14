from src.data_analysis.utils import *

def get_device_year_dict(file) -> dict[str, str]:
    """
    Reads a JSON file and returns a dictionary containing device-year information.

    Parameters:
        file (str): The path to the JSON file.

    Returns:
        dict[str, str]: key: device name, value: year
    """
    device_year = {}
    with open(file, 'r') as f:
        device_year = json.load(f)
    for device in device_year:
        device_year[device] = device_year[device].split('-')[0]
    return device_year

def get_device_category_dict(file, get_manufacturer=0) -> dict[str, str]:
    """
    Retrieves a dictionary mapping device names to their corresponding categories or manufacturers.

    Args:
        file (str): The path to the input file.
        get_manufacturer (int, optional): Flag indicating whether to retrieve the manufacturer dictionary.
            Defaults to 0.

    Returns:
        dict[str, str]: A dictionary mapping device names to their corresponding categories or manufacturers.
    """
    device_category = {}
    device_manufacturer = {}
    device_platform = {}
    device_os = {}
    with open(file, 'r') as f:
        reader = csv.reader(f)
        next(reader)  # Skip the header
        for row in reader:
            category, device, mac_address, manufacturer, platform, os = [field.strip() for field in row]
            if not device:  # Skip if device is an empty string
                continue
            device_category[device] = category
            device_manufacturer[device] = manufacturer if manufacturer else 'Other'
            device_platform[device] = platform if platform else 'Other'
            device_os[device] = os if os else 'Other'
            
    if get_manufacturer == 1:
        return device_manufacturer
    elif get_manufacturer == 2:
        return device_platform
    elif get_manufacturer == 3:
        return device_os
    return device_category

def get_device_functionality_dict(device_list)-> dict[bool, bool]:
    device_functionality = {}
    ipv6_only_functionaly_devices = ['facebook-portal-mini', 'google-home-mini', 'google-nest-mini1', 'nest-hub', 'nest-hub-max', 'appletv', 'chromecast-googletv', 'tivostream']
    for device in device_list:
        device_functionality[device] = 1 if device in ipv6_only_functionaly_devices else 0
    return device_functionality

def get_ipv6_device_mappings(device_ip_json, device_list)-> dict[str, list[str]]:
    ip_device_mapping = {}
    with open(device_ip_json, 'r') as f:
        device_ipv6_address = json.load(f)
        for device in device_list:
            if device not in device_ipv6_address:
                device_ipv6_address[device] = []
            else:
                gua_addresses = device_ipv6_address[device].get('gua')
                ula_addresses = device_ipv6_address[device].get('ula')
                lla_addresses = device_ipv6_address[device].get('lla')
                device_ipv6_address[device] = gua_addresses + ula_addresses + lla_addresses
                
        for device in device_ipv6_address:
            for addr in device_ipv6_address[device]:
                ip_device_mapping[addr] = device
    return ip_device_mapping

def get_device_ipv6_address_dict(device_ip_json, device_list)-> dict[str, dict[str, list[str]]]:
    logger.info(f"Running get_device_ipv6_address_dict {device_ip_json}")
    start_time = time.time()
    with open(device_ip_json, 'r') as f:
        device_ipv6_address_type = json.load(f)

        for device in device_list:
            if device in device_ipv6_address_type:
                gua_addresses = device_ipv6_address_type[device].get('gua')
                eui64_address = set()
                if len(gua_addresses) != 0:
                    eui64_address = find_eui64_address(device, gua_addresses)
                device_ipv6_address_type[device]['GUA EUI-64 Address'] = list(eui64_address) if eui64_address else []

                ula_addresses = device_ipv6_address_type[device].get('ula')
                lla_addresses = device_ipv6_address_type[device].get('lla')
                # if ula_addresses or lla_addresses:
                eui64_address = set()
                if len(ula_addresses) != 0:
                    eui64_address.update(find_eui64_address(device, ula_addresses))
                if len(lla_addresses) != 0:
                    eui64_address.update(find_eui64_address(device, lla_addresses))
                device_ipv6_address_type[device]['Local EUI-64 Address'] = list(eui64_address) if eui64_address else []
                if len(gua_addresses) == 0 and len(ula_addresses) == 0 and len(lla_addresses) == 0:
                    device_ipv6_address_type[device]['NDP Traffic No Addr'] = 1
                else:
                    device_ipv6_address_type[device]['NDP Traffic No Addr'] = 0
            else:
                device_ipv6_address_type[device] = {'gua': [], 'ula': [], 'lla': [], 'GUA EUI-64 Address': [], 'Local EUI-64 Address': [], 'NDP Traffic No Addr': 0}
    in_dir = os.path.dirname(device_ip_json)
    for device in device_list:
        filepath = os.path.join(in_dir, device, 'ns.csv')
        
        device_ipv6_address_type[device]['Unused GUA'] = set()
        device_ipv6_address_type[device]['Unused ULA'] = set()
        device_ipv6_address_type[device]['Unused LLA'] = set()
        device_ipv6_address_type[device]['Unused GUA EUI-64'] = set()
        if not os.path.exists(filepath):
            continue
        gua_set = set(device_ipv6_address_type[device]['gua'])
        ula_set = set(device_ipv6_address_type[device]['ula'])
        lla_set = set(device_ipv6_address_type[device]['lla'])
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['src_ip'] == "::" and address.is_eui64_address(row['mac'], row['target']):
                    target_ip = row['target']
                    if address.check_ipv6_global_unicast(target_ip):
                        if target_ip not in gua_set:
                            device_ipv6_address_type[device]['Unused GUA'].add(target_ip)
                    elif address.check_ipv6_link_local_addr(target_ip):
                        if target_ip not in lla_set:
                            device_ipv6_address_type[device]['Unused LLA'].add(target_ip)
                    elif address.check_ipv6_unique_local(target_ip):
                        if target_ip not in ula_set:
                            device_ipv6_address_type[device]['Unused ULA'].add(target_ip)
        unused_gua_eui64 = find_eui64_address(device, list(device_ipv6_address_type[device]['Unused GUA']))
        device_ipv6_address_type[device]['Unused GUA EUI-64'] = set(unused_gua_eui64)
    
    logger.info(f"get_device_ipv6_address_dict took {time.time() - start_time} seconds")
    return device_ipv6_address_type

def get_dhcpv6_req_dict(input_dir, device_list)-> dict[str, dict[str, bool]]:
    logger.info("Running get_dhcpv6_req_dict")
    start_time = time.time()
    dhcpv6_req_dict = {}
    for device in device_list:
        dhcpv6_req_dict[device] = {'Stateful DHCPv6': 0, 'Stateless DHCPv6': 0}
        filepath = os.path.join(input_dir, device, 'DHCP_Information_Requests.csv')
        if not os.path.exists(filepath):
            continue
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if dhcpv6_req_dict[device]['Stateless DHCPv6'] == 1:
                    break
                req_opts = row['requested_options'].split(';')
                dhcpv6_req_dict[device]['Stateless DHCPv6'] = 1 if '23' in req_opts else 0
                        
        if dhcpv6_req_dict[device]['Stateless DHCPv6'] == 0:
            with open(os.path.join(input_dir, device, 'DHCP_Solicits.csv'), 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if dhcpv6_req_dict[device].get('Stateless DHCPv6'):
                        break
                    req_opts = row['requested_options'].split(';')
                    dhcpv6_req_dict[device]['Stateless DHCPv6'] = 1 if '23' in req_opts else 0
        with open(os.path.join(input_dir, device, 'DHCP_Reply.csv'), 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if dhcpv6_req_dict[device].get('Stateful DHCPv6'):
                    break
                iata_ip = row['iata_ip']
                iana_ip = row['iana_ip']
                if iana_ip or iata_ip:
                    dhcpv6_req_dict[device]['Stateful DHCPv6'] = 1
    
    logger.info(f"get_dhcpv6_req_dict took {time.time() - start_time} seconds")
    return dhcpv6_req_dict


def get_dns_dict(input_dir, device_list)-> dict[str, dict[str, int]]:
    logger.info("Running get_dns_dict")
    mac_dict = read_mac_address()
    start_time = time.time()
    # from src.protocols.dns import DNSParser
    # response_codes = DNSParser.response_codes
    dns_dict = {}
    error_code_dict = {}
    none_aa_dns_res = {}
    for device in device_list:
        keys = ['IPv6 DNS', 'AAAA Req', 'AAAA IPv6 Req', 'A only Req in IPv6', 'AAAA Req only in IPv4', \
            'HTTPS Req', 'SVCB Req', 'EUI-64 DNS Req',\
            'AAAA Res', 'AAAA IPv6 Res', 'AAAA Res Errorcode', 'SRV Res', 'AAAA SOA Res', 'SOA Res', 'A Res',\
                'AAAA Req No AAAA Res', 'AAAA req Got A Res only', 'only AAAA Req But Got A Res',\
                'HTTPS Res', 'SVCB Res']
        dns_dict[device] = {key: set() if key not in ['IPv6 DNS', 'EUI-64 DNS Req'] else 0 for key in keys}
        routed_ipv6_dns_req = set()
        filepath = os.path.join(input_dir, device, 'DNS_Requests.csv')
        if not os.path.exists(filepath):
            continue
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['mac'] != mac_dict[device]:  # not DNS from the device. It's traffic routed by hubs 
                    routed_ipv6_dns_req.add(zip(row['query_name'], row['tsn_id']))
                    continue
                if dns_dict[device]['IPv6 DNS'] == 0 and int(row['version'])==6:
                    dns_dict[device]['IPv6 DNS'] = 1
                if zip(row['query_name'], row['tsn_id']) in routed_ipv6_dns_req:
                    continue
                if dns_dict[device]['EUI-64 DNS Req'] == 0 and int(row['version'])==6 and address.is_eui64_address(row['mac'], row['src_ip']):
                    dns_dict[device]['EUI-64 DNS Req'] = 1
                
                if row['query_type'] == 'AAAA':
                    # and row['dns_resolver_ip'] in ['2001:4860:4860::8888', '2001:4860:4860::8844']:
                    dns_dict[device]['AAAA Req'].add(row['query_name'])
                    # AAAA in IPv6
                    if int(row['version'])==6:
                        dns_dict[device]['AAAA IPv6 Req'].add(row['query_name'])
                    else:
                        # AAAA in IPv4
                        dns_dict[device]['AAAA Req only in IPv4'].add(row['query_name'])
                # A in IPv6 - AAAA in IPv6 = A only DNS Req in IPv6
                elif row['query_type'] == 'A' and int(row['version'])==6:
                    #and row['dns_resolver_ip'] in ['2001:4860:4860::8888', '2001:4860:4860::8844']:
                    dns_dict[device]['A only Req in IPv6'].add(row['query_name'])
                
                    
                # A in IPv4
                elif int(row['version'])==4: # row['query_type'] == 'A' and 
                    pass
                elif row['query_type'] == 'HTTPS':
                    dns_dict[device]['HTTPS Req'].add(row['query_name'])
                elif row['query_type'] == 'SVCB':
                    dns_dict[device]['SVCB Req'].add(row['query_name'])
                else:
                    pass
                    # logger.debug(f'{device}: unknown DNS request type {row["query_type"]} {row["query_name"]} {row["dns_resolver_ip"]}')
                    
                    
        with open(os.path.join(input_dir, device, 'DNS_Responses.csv'), 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['ans_type'] == 'CNAME': # int(row['version']) == 4 or
                    continue
                if zip(row['query_name'], row['tsn_id']) in routed_ipv6_dns_req:
                    continue
                errorcode = int(row['status'])
                # if errorcode != 3 and errorcode != 0 and errorcode != 12 and errorcode != 13:
                #     logger.debug(f'{device}: DNS response code {row["query_name"]} {row["ans_data"]} {row["status"]}')
                if row['ans_type'] == 'A':
                    if errorcode == 0:
                        dns_dict[device]['A Res'].add(row['query_name'])
                elif row['ans_type'] == 'AAAA' and address.is_ipv6(row['ans_data']) and errorcode == 0:
                    dns_dict[device]['AAAA Res'].add(row['query_name'])
                    if int(row['version']) == 6:
                        dns_dict[device]['AAAA IPv6 Res'].add(row['query_name'])
                elif row['ans_type'] == 'AAAA' and (errorcode != 0):     # All zero in the final table
                    dns_dict[device]['AAAA Res Errorcode'].add(row['query_name'])
                elif row['ans_type'] == 'SRV' and address.validate_ip_address(row['ans_data']) == False:    # All zero in the final table
                    dns_dict[device]['SRV Res'].add(row['query_name'])
                elif row['ans_type'] == 'SOA':
                    if (errorcode == 3 or errorcode == 12):
                        dns_dict[device]['AAAA SOA Res'].add(row['query_name'])
                    else:
                        dns_dict[device]['SOA Res'].add(row['query_name'])
                elif row['ans_type'] == 'HTTPS':
                    dns_dict[device]['HTTPS Res'].add(row['query_name'])
                elif row['ans_type'] == 'SVCB':
                    dns_dict[device]['SVCB Res'].add(row['query_name'])
                elif row['ans_type'] == 'OPT' or row['ans_type'] == 'TXT':
                    pass
                else:
                    pass
                    # logger.debug(f'{device}: unknown DNS response type {row["query_name"]} {row["ans_type"]} {row["status"]}')
        
        a_dns_req = dns_dict[device]['A only Req in IPv6']
        # only sent A DNS req without AAAA req in IPv6
        dns_dict[device]['A only Req in IPv6'] = dns_dict[device]['A only Req in IPv6'].difference(dns_dict[device]['AAAA IPv6 Req'])
        # only sent AAAA DNS Req only in IPv4 but not in IPv6  - hybrid experiments
        dns_dict[device]['AAAA Req only in IPv4'] = dns_dict[device]['AAAA Req only in IPv4'].difference(dns_dict[device]['AAAA IPv6 Req'])
        
        
        # AAAA req, received only A DNS res without AAAA res
        a_dns_res = set(dns_dict[device].get('A Res', []))
        aaaa_dns_req = set(dns_dict[device].get('AAAA Req', []))
        aaaa_dns_res = set(dns_dict[device].get('AAAA Res', []))
        dns_dict[device]['AAAA req Got A Res only'] = a_dns_res & (aaaa_dns_req - aaaa_dns_res)
        
        # Send AAAA Req but without AAAA Res
        dns_dict[device]['AAAA Req No AAAA Res'] = aaaa_dns_req - aaaa_dns_res
        

        # Only sent AAAA req, not A, but got A res instead of AAAA 
        dns_dict[device]['only AAAA Req But Got A Res'] = (a_dns_res - a_dns_req) & (aaaa_dns_req - aaaa_dns_res)
                
    logger.info(f"get_dns_dict took {time.time() - start_time} seconds")
    return dns_dict

def get_data_dict(input_dir, experiment_name, device_list)-> list[dict[str, dict[str, int]],dict[str, set[str]], dict[str, dict[str,set[str]]], dict[str, dict[str,set[str]]]]:
    logger.info("Running get_data_dict")
    start_time = time.time()
    data_dict = {}
    global_eui64_destination = {}
    destination_name_dict = {'Global':{}, 'Local':{}}
    destination_name_per_version= {'IPv6': {}, 'IPv4': {}}
    ip_domain_mapping_file = '%s/dest-analysis/output' % destination_analysis_path
    ip_domain_mapping = pickle.load(open(f'{ip_domain_mapping_file}/all_ip_hosts_all.model', 'rb'))
    ip_device_mapping = get_ipv6_device_mappings(f'{input_dir}/device_ip_{experiment_name}.json', device_list)
    for device in device_list:
        data_dict[device] = {'Local Data Comm': 0, 'Global Data Comm': 0, 'Data': 0, 'Local Data Comm EUI-64': 0, 'Global Data Comm EUI-64': 0, 'Data EUI-64': 0, 'Global Data Comm Volume': 0, 'Global Data Comm IPv6 Volume':0, 'Global Data Comm IPv4 Volume':0 }
        global_eui64_destination[device] = set()
        destination_name_dict['Global'][device] = set()
        destination_name_dict['Local'][device] = set()
        destination_name_per_version['IPv6'][device] = set()
        destination_name_per_version['IPv4'][device] = set()
        
        filepath = os.path.join(input_dir, device, 'Data.csv')
        if not os.path.exists(filepath):
            continue
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if data_dict[device]['Data'] == 0:
                    data_dict[device]['Data'] = 1
                
                version = int(row['version'])
                eui_64 = 0
                if row['flow'] == 'Outgoing':
                    my_ipv6 = row['src_ip']
                else:
                    my_ipv6 = row['dest_ip']
                if version == 6 and address.is_eui64_address(row['mac'], my_ipv6):
                    eui_64 = 1
                    data_dict[device]['Data EUI-64'] = 1
            
                # src_type = address.get_ipv6_type_binary(row['src_ip'])
                # dst_type = address.get_ipv6_type_binary(row['dest_ip'])
                # if src_type == 0 and dst_type == 0: # global
                if row['type'] == 'Global':
                    data_dict[device]['Global Data Comm'] += int(row['count'])
                    data_dict[device]['Global Data Comm Volume'] += int(row['size'])
                    if version == 6:
                        data_dict[device]['Global Data Comm IPv6 Volume'] += int(row['size'])
                    else:
                        data_dict[device]['Global Data Comm IPv4 Volume'] += int(row['size'])
                    if eui_64:
                        data_dict[device]['Global Data Comm EUI-64'] += int(row['count'])
                        if row['flow'] == 'Outgoing':
                            dest_domain = ip_domain_mapping[device].get(row['dest_ip'], row['dest_ip'])
                            if dest_domain.startswith('2001:470:8863:1aba') or dest_domain.startswith('fe80') or dest_domain.startswith('fd'):
                                continue
                            global_eui64_destination[device].add(dest_domain)
                    # get destination domain name
                    if row['flow'] == 'Outgoing':
                        dest_domain = ip_domain_mapping[device].get(row['dest_ip'], row['dest_ip'])
                    else:
                        dest_domain = ip_domain_mapping[device].get(row['src_ip'], row['src_ip'])
                    if dest_domain.startswith('2001:470:8863:1aba') or dest_domain.startswith('fe80') or dest_domain.startswith('fd'):
                        continue
                    destination_name_dict['Global'][device].add(dest_domain)
                    if version == 6:
                        destination_name_per_version['IPv6'][device].add(dest_domain)
                    else:
                        destination_name_per_version['IPv4'][device].add(dest_domain)
                else:   # Local traffic Local or Matter
                    data_dict[device]['Local Data Comm'] += int(row['count'])
                    if eui_64:
                        data_dict[device]['Local Data Comm EUI-64'] += int(row['count'])
                    
                    # get destination device
                    if row['flow'] == 'Outgoing':
                        dest_device = ip_device_mapping.get(row['dest_ip'], row['dest_ip'])
                    else:
                        dest_device = ip_device_mapping.get(row['src_ip'], row['src_ip'])
                    destination_name_dict['Local'][device].add(dest_device)
                    
                
    logger.info(f"get_data_dict took {time.time() - start_time} seconds")
    return [data_dict, global_eui64_destination, destination_name_dict, destination_name_per_version]
