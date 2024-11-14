import os
import sys
import json
# from scapy.all import Ether, IP, IPv6
# from scapy.all import *
import pyshark
# from ipaddress import ip_address
from collections import defaultdict
from multiprocessing import Pool, cpu_count

def expand_mac_address(mac_address:str) -> str:
    octets = mac_address.split(":")
    octets = [octet.zfill(2).lower() for octet in octets]
    return ":".join(octets)

def read_mac_address(file) -> dict:
    mac_file = file
    mac_dic = {}
    with open(mac_file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if len(line.split(' ')) < 2 or line.startswith(' ') or line.startswith('/n'):
                continue
            tmp_mac, tmp_device = line[:-1].split(' ')
            if len(tmp_mac) != 17:
                tmp_mac = expand_mac_address(tmp_mac)
            mac_dic[tmp_mac.lower()] = tmp_device
    return mac_dic

def process_pcap(args):
    pcap_path, devices = args
    ipv4_addresses = defaultdict(set)
    ipv6_addresses = defaultdict(set)

    cap = pyshark.FileCapture(pcap_path, display_filter='icmpv6')
    
    for packet in cap:
        try:
            src_mac = packet.eth.src.lower()
            dst_mac = packet.eth.dst.lower()

            # if hasattr(packet, 'ip'):
            #     process_ip(packet.ip.src, src_mac, devices, ipv4_addresses)
            #     process_ip(packet.ip.dst, dst_mac, devices, ipv4_addresses)
            if hasattr(packet, 'ipv6'):
                process_ip(packet.ipv6.src, src_mac, devices, ipv6_addresses)
                process_ip(packet.ipv6.dst, dst_mac, devices, ipv6_addresses)
        except AttributeError:
            continue

    cap.close()
    return ipv4_addresses, ipv6_addresses

def process_ip(ip, mac, devices, ip_dict):
    if mac in devices:
        device_name = devices[mac]
        if ip == "0.0.0.0" or ip == "::":
            return
        ip_dict[device_name].add(ip)

def save_json(data, filename):
    # Convert sets to lists for JSON serialization
    serializable_data = {k: list(v) for k, v in data.items()}
    with open(filename, 'w') as f:
        json.dump(serializable_data, f, indent=4)

def main():
    pcap_directory = sys.argv[1]
    devices_file = 'devices-ipv6-mac.txt'

    devices = read_mac_address(devices_file)
    pcap_files = [os.path.join(pcap_directory, f) for f in os.listdir(pcap_directory) if f.endswith('.pcap')]
        
    # Use multiprocessing to process PCAPs in parallel
    with Pool(cpu_count()) as pool:
        results = pool.map(process_pcap, [(pcap, devices) for pcap in pcap_files])

    # Combine results from all processes
    ipv4_addresses = defaultdict(set)
    ipv6_addresses = defaultdict(set)
    for ipv4, ipv6 in results:
        for device, ips in ipv4.items():
            ipv4_addresses[device].update(ips)
        for device, ips in ipv6.items():
            ipv6_addresses[device].update(ips)
    
    # save_json(ipv4_addresses, '2024aug/ipv4_addresses.json')
    save_json(ipv6_addresses, '2024aug/ipv6_addresses.json')

if __name__ == "__main__":
    main()