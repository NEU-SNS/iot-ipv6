#!~/.venvs/ipv6/bin/python3
from src.helper import *
from src.protocols import *
from src.helper.utils import *
from src.helper.logger import setup_logger
import concurrent.futures
import time

logger = None
mac_dict = {}
inv_mac_dict = {}

def print_usage(is_error:bool) -> None:
    ANALYSIS_USAGE = """Usage: %s <decoded pcap directory> <output directory> [-e <experiment name>] [--out_only] 
    || out_only: Save data from database to csv files
    """ % sys.argv[0]
    print(ANALYSIS_USAGE, file=sys.stderr) if is_error else print(ANALYSIS_USAGE)
    exit(is_error)
    
def argument_parsing():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("in_dir")
    parser.add_argument("out_dir")
    parser.add_argument("-e", "--experiment", dest="experiment_name", default=1)
    parser.add_argument("--out_only", dest="out_only", default=False, action='store_const', const=True, help="Save data from database to csv files")
    args = parser.parse_args()
    if len(sys.argv) < 3:
        print_usage(1)
    
    in_dir = args.in_dir
    out_dir = args.out_dir
    experiment_name = args.experiment_name
    out_only = args.out_only
    
    if not os.path.exists(out_dir):
        os.system('mkdir -pv %s' % out_dir)
        
    errors = False
    if not os.path.isdir(in_dir):
        errors = True
        print(INVAL % ("Decoded pcap directory", in_dir, "directory"), file=sys.stderr)
    else:
        if not os.access(in_dir, os.R_OK):
            errors = True
            print(NO_PERM % ("decoded pcap directory", in_dir, "read"), file=sys.stderr)
        if not os.access(in_dir, os.X_OK):
            errors = True
            print(NO_PERM % ("decoded pcap directory", in_dir, "execute"), file=sys.stderr)
    if os.path.isdir(out_dir):
        if not os.access(out_dir, os.W_OK):
            errors = True
            print(NO_PERM % ("output directory", out_dir, "write"), file=sys.stderr)
        if not os.access(out_dir, os.X_OK):
            errors = True
            print(NO_PERM % ("output directory", out_dir, "execute"), file=sys.stderr)

    if errors:
        print_usage(1)
    
    return in_dir, out_dir, experiment_name, out_only

def get_pcap(input_folder:str) -> dict:
    
    device_file_dict = {}
    for file_name in os.listdir(input_folder):
        if file_name.startswith(".") or file_name.startswith("log"):
            continue
        device = file_name.split('.')[0].split('_')[0]
        if device not in device_file_dict:
            device_file_dict[device] = []
        full_dec_file = os.path.join(input_folder, file_name)
        if not full_dec_file.endswith(".pcap"):
            print(WRONG_EXT % ("input file", "PCAP", full_dec_file), file=sys.stderr)
            continue
        if not os.access(full_dec_file, os.R_OK):
            print(NO_PERM % ("input file", full_dec_file, "read"), file=sys.stderr)
            continue
        device_file_dict[device].append(full_dec_file)
    
    return device_file_dict
    
def init(device_file:str="devices-ipv6.txt"):
    global mac_dict, inv_mac_dict
    mac_dict = utils.read_mac_address()
    inv_mac_dict = {v: k for k, v in mac_dict.items()}
    device_list = []
    with open(device_file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith(' ') or line.startswith('\n'):
                continue
            device_list.append(line.strip())
    
    return device_list
    


def pcap_reader(device, file_path, experiment_name, out_dir):
    dbcon, cur = setdb.setup_exp_db(experiment_name, out_dir, device)

    device_ips = set()
    with PcapReader(f"{file_path}") as pcap_reader:
        count = 0
        other_device_ip_mac = {}
        warning_address = set()
        for packet in pcap_reader:
            count += 1
            try:
                if packet.haslayer('Ether') and packet.haslayer('IPv6'):
                    if packet['IPv6'].version!=6:
                        logger.warning(f"Bogus packet {device} {packet.time}: {packet}")
                        continue
                    nh = packet['IPv6'].nh
                    # find the IPv6 address of this device based on mac address
                    src_mac = expand_mac_address( packet['Ether'].src)
                    dst_mac = expand_mac_address( packet['Ether'].dst)
                    src_ipv6 = packet['IPv6'].src
                    dst_ipv6 = packet['IPv6'].dst
                    device_mac = mac_dict[device]
                    ## merge data from devices with two mac addresses
                    if device not in ['appletv', 'sengled-hub', 'samsungtv65-wifi']:
                        my_ipv6 = src_ipv6 if src_mac == device_mac else dst_ipv6
                    else:
                        if device == 'appletv':
                            device_mac_list = ['08:66:98:a2:21:9e', '08:66:98:a2:21:9c']
                        elif device == 'sengled-hub':
                            device_mac_list = ['b0:ce:18:27:9f:e4', 'b0:ce:18:27:9f:e5']
                        elif device == 'samsungtv65-wifi':
                            device_mac_list = ['1c:af:4a:8b:f9:e8', 'c8:12:0b:f9:f9:14']
                        if src_mac in device_mac_list:
                            my_ipv6 = src_ipv6
                        else:
                            my_ipv6 = dst_ipv6
                    # if device != 'samsung-fridge':
                    # nest-hub: ipv6.dst==2001:4860:4860::8888 and eth.dst==d8:eb:46:71:c7:0e
                    # 2001:470:8863:1aba:388b:3766:9cb:bfa9 -> samsung-fridge
                    # 2001:470:8863:1aba:1bde:c3fd:10d5:2d36 -> nest-hub
                    # some smart hubs may route traffic they received, which would polute the source mac address
                    if nh == 6 or nh == 17:
                        if src_mac == device_mac and dst_mac != "36:22:7b:87:51:6f": # router mac address
                            other_device_ip_mac[dst_ipv6]=dst_mac
                        elif dst_mac == device_mac and src_mac != "36:22:7b:87:51:6f":
                            other_device_ip_mac[src_ipv6]=src_mac
                        if my_ipv6 in other_device_ip_mac:
                            if my_ipv6 not in warning_address:
                                logger.warning(f"{device} {packet.time}: {my_ipv6} from {other_device_ip_mac[my_ipv6]}")
                                warning_address.add(my_ipv6)
                            my_ipv6 = None
                    
                    if nh == 0 or nh==44: # hop-by-hop option and fragment header option
                        try:
                            nh = packet['IPv6'].payload.nh
                        except:
                            logger.debug(f'{device}: No IPv6 Packet NH {count=}: {packet}')
                            # pass
                    if nh==58:  # ICMPv6
                        icmpv6_type = packet['IPv6'].type
                        if icmpv6_type not in [1,2,3,4,100,101,127]: # Ignore ICMPv6 error messages: this will cause a bug on src_ipv6 and dst_ipv6
                            device_ips.add(my_ipv6)
                            if icmpv6_type == 128 and dst_ipv6 == "ff02::1":
                                logger.warning(f"{device} {packet.time}: SCANNING NETWORK {packet}")
                        if icmpv6_type in [133, 134, 135, 136, 137]: # ICMPv6 NDP packets. 
                            # It's interesting seeing that the type of ICMPv6 is in IPv6.type. Scapy doesn't have a general ICMPv6 or DHCPv6 class. 
                            icmpv6.ICMPv6Parser.packet_parser(packet, device=device, table=cur, addresses=[src_mac, dst_mac, src_ipv6, dst_ipv6, my_ipv6])
                            # if icmpv6_type == 135 and src_ipv6=="::":
                            #     if address.is_eui64_address(src_mac, packet['ICMPv6ND_NS'].tgt):
                            #         device_ips.add(packet['ICMPv6ND_NS'].tgt)
                    elif nh == 17 and dhcpv6.DHCPv6Parser.isDHCPv6(packet):
                        device_ips.add(my_ipv6)
                        dhcpv6.DHCPv6Parser.packet_parser(packet, device=device, table=cur, addresses=[src_mac, dst_mac, src_ipv6, dst_ipv6, my_ipv6])
                    elif nh == 17 and dns.DNSParser.isDNS(packet):
                        device_ips.add(my_ipv6)
                        sport = packet['UDP'].sport
                        dport = packet['UDP'].dport
                        dns.DNSParser.packet_parser(packet, device=device, table=cur, addresses=[src_mac, dst_mac, src_ipv6, dst_ipv6, my_ipv6, sport, dport])
                    elif nh == 6 or nh == 17: # ipv6data.DataParser.isDataPacket(packet):
                        device_ips.add(my_ipv6)
                        ipv6data.DataParser.packet_parser(packet, device=device, table=cur, version=6, addresses=[src_mac, dst_mac, src_ipv6, dst_ipv6, my_ipv6, device_mac])
                    else:
                        logger.debug(f'{device}: Unknown IPv6 Packet {count=} Type {nh=}: {packet}')
                        pass
                    
                elif packet.haslayer('Ether') and packet.haslayer('IP'):
                    # IPv4: DNS. 
                    proto = packet['IP'].proto
                    src_mac = expand_mac_address( packet['Ether'].src)
                    dst_mac = expand_mac_address( packet['Ether'].dst)
                    src_ip = packet['IP'].src
                    dst_ip = packet['IP'].dst
                    device_mac = mac_dict[device]
                    if device not in ['appletv', 'sengled-hub', 'samsungtv65-wifi']:
                        my_ip = src_ip if src_mac == device_mac else dst_ip
                    else:
                        if device == 'appletv':
                            device_mac_list = ['08:66:98:a2:21:9e', '08:66:98:a2:21:9c']
                        elif device == 'sengled-hub':
                            device_mac_list = ['b0:ce:18:27:9f:e4', 'b0:ce:18:27:9f:e5']
                        elif device == 'samsungtv65-wifi':
                            device_mac_list = ['1c:af:4a:8b:f9:e8', 'c8:12:0b:f9:f9:14']
                        if src_mac in device_mac_list:
                            my_ip = src_ip
                        else:
                            my_ip = dst_ip
                    if proto == 17 and dns.DNSParser.isDNS(packet):
                        sport = packet['UDP'].sport
                        dport = packet['UDP'].dport
                        # dns.DNSParser.packet_parser(packet, device=device, table=cur, addresses=[src_mac, dst_mac, src_ip, dst_ip, my_ip, sport, dport])
                    elif proto == 6 or proto == 17: 
                        if (src_mac == utils.ROUTER_MAC or dst_mac == utils.ROUTER_MAC):
                            ipv6data.DataParser.packet_parser(packet, device=device, table=cur, version=4, addresses=[src_mac, dst_mac, src_ip, dst_ip, my_ip, device_mac])
            except StopIteration as e:
                logger.debug(f"{device} {file_path} file is empty" )
                return
            except IntegrityError as e:
                continue
            except Exception as e:
                logger.error(f"{device}: An exception of type {type(e).__name__} occurred: {e}")
                traceback.print_exc()
                return
    dbcon.commit()
    cur.close()
    dbcon.close()
    return device, device_ips, time.time()
        


def save_device_ip(device_ip_dict, out_dir, experiment_name):
    device_ip_dict_out = {}
    for device in device_ip_dict:
        ips = device_ip_dict[device]
        if len(ips) == 0:
            continue
        device_ip_dict_out[device] = {'gua': [], 'lla': [], 'ula': []}
        for ip in ips:
            if not ip:
                continue
            if address.is_ipv6(ip):
                if address.check_ipv6_global_unicast(ip):
                    if not ip.startswith(GLOBAL_IPV6_PREFIX):
                        logger.warning(f'{device}: Out of scope global IP {ip}')
                        continue
                    device_ip_dict_out[device]['gua'].append(ip)
                elif address.check_ipv6_link_local_addr(ip):
                    device_ip_dict_out[device]['lla'].append(ip)
                elif address.check_ipv6_unique_local(ip):
                    device_ip_dict_out[device]['ula'].append(ip)
                elif address.check_ipv6_unspecified(ip):
                    logger.debug(f"{device=}: {ip=} is an unspecified IPv6 address")
                else:
                    logger.error(f"{device=}: {ip=} is an unknown invalid IPv6 address")
            
    with open(f"{out_dir}/device_ip_{experiment_name}.json", 'w') as f:
        json.dump(device_ip_dict_out, f, indent=4)
    return 0


def init_database(experiment_name:str, out_dir:str, device:str) -> bool:

    dbcon = 0
    cur = 0
    dbcon, cur = setdb.setup_exp_db(experiment_name, out_dir, device)
    setdb.drop_tables(cur)
    setdb.create_tables(cur)
    logger.info(f"Set up {device} database")
    if cur == 0:
        logger.error("Unable to set up database")
    dbcon.commit()
    cur.close()
    dbcon.close()
    return 0

def close_database(experiment_name, out_dir, device):
    dbcon, cur = setdb.setup_exp_db(experiment_name, out_dir, device)
    dbcon.commit()
    if not os.path.exists(os.path.join(out_dir, device)):
        os.system('mkdir -pv %s' % os.path.join(out_dir, device))
    out_dir = os.path.join(out_dir, device)
    # res = cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;")
    # for name in res.fetchall():
    #     logger.info(f'Table: {name[0]}')
    
    db_df = pd.read_sql_query("SELECT * FROM RS", dbcon)
    db_df.to_csv(f'{out_dir}/rs.csv', index=False)
    db_df = pd.read_sql_query("SELECT * FROM RA", dbcon)
    db_df.to_csv(f'{out_dir}/ra.csv', index=False)
    db_df = pd.read_sql_query("SELECT * FROM NS", dbcon)
    db_df.to_csv(f'{out_dir}/ns.csv', index=False)
    db_df = pd.read_sql_query("SELECT * FROM NA", dbcon)
    db_df.to_csv(f'{out_dir}/na.csv', index=False)
    
    
    db_df = pd.read_sql_query("SELECT * FROM DNS_Requests", dbcon)
    db_df.to_csv(f'{out_dir}/DNS_Requests.csv', index=False)
    db_df = pd.read_sql_query("SELECT * FROM DNS_Responses", dbcon)
    db_df.to_csv(f'{out_dir}/DNS_Responses.csv', index=False)
    db_df = pd.read_sql_query("SELECT * FROM MDNS_Requests", dbcon)
    db_df.to_csv(f'{out_dir}/MDNS_Requests.csv', index=False)
    db_df = pd.read_sql_query("SELECT * FROM MDNS_Responses", dbcon)
    db_df.to_csv(f'{out_dir}/MDNS_Responses.csv', index=False)

    db_df = pd.read_sql_query("SELECT * FROM DHCP_Information_Requests", dbcon)
    db_df.to_csv(f'{out_dir}/DHCP_Information_Requests.csv', index=False)
    db_df = pd.read_sql_query("SELECT * FROM DHCP_Solicits", dbcon)
    db_df.to_csv(f'{out_dir}/DHCP_Solicits.csv', index=False)
    db_df = pd.read_sql_query("SELECT * FROM DHCP_Requests", dbcon)
    db_df.to_csv(f'{out_dir}/DHCP_Requests.csv', index=False)
    db_df = pd.read_sql_query("SELECT * FROM DHCP_Reply", dbcon)
    db_df.to_csv(f'{out_dir}/DHCP_Reply.csv', index=False)
    db_df = pd.read_sql_query("SELECT * FROM DHCP_Advertisements", dbcon)
    db_df.to_csv(f'{out_dir}/DHCP_Advertisements.csv', index=False)
    db_df = pd.read_sql_query("SELECT * FROM Data", dbcon)
    db_df.to_csv(f'{out_dir}/Data.csv', index=False)

    cur.close()
    dbcon.close()
    return 0

def main():
    [ print_usage(0) for arg in sys.argv if arg in ("-h", "--help") ]
    
    in_dir, out_dir, experiment_name, out_only = argument_parsing()
    global logger
    if not os.path.exists('logs'):
        os.system('mkdir -pv logs')
    logger = setup_logger('IoTv6', f"logs/{experiment_name}.log", logging.DEBUG)
    logger.info("Running %s..." % sys.argv[0])
    logger.info("Input files located in: %s\n Output files placed in: %s\n" % (in_dir, out_dir))

    # print(mac_dict)
    start_time = time.time()
    # a dictionary of device files: key is device name. value is the list of pcap files
    device_file_dict = get_pcap(in_dir)
    
    device_list = init()
    
    logger.info(device_file_dict)
    
    
    device_ip_dict = {}
    

    max_threads = 64  # Set the maximum number of threads to run concurrently
    device_time = time.time()
    if not out_only:
        # extract features from pcap files
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            for device in device_list:
                if device in device_file_dict:

                    file_path = device_file_dict[device]
                    init_database(experiment_name, out_dir, device)
                    for file in file_path:
                        logger.info(f"Reading {device}: {file}")
                        future = executor.submit(pcap_reader, device, file, experiment_name, out_dir)
                        futures.append(future)
                else:
                    logger.info(f"{experiment_name}: {device} has no traffic")
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result is not None:
                    device, ips, end_time = result
                    logger.info(f"Time taken for {device}: {end_time-device_time}")
                    device_ip_dict[device] = device_ip_dict.get(device, set()) | ips
                    close_database(experiment_name, out_dir, device)

        save_device_ip(device_ip_dict, out_dir, experiment_name)
    else:
        # save data from database to csv files
        for device in device_file_dict.keys():
            close_database(experiment_name, out_dir, device)
    end_time = time.time()
    logger.info(f"Time taken: {end_time-start_time}")
    return 0

if __name__ == "__main__":
    
    main()
    
    