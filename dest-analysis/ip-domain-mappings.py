import sys
import os
import json
import ipaddress
import numpy as np
import pickle
import collections
from collections import Counter
from copy import deepcopy
import concurrent.futures

def print_usage(is_error):
    PATH = sys.argv[0]
    USAGE = """
    Usage: python3 {prog_name} input/input_dns_file.txt out_dir

    This file extracts ip-host tuple from dns and tls messages. 

    inputs/input_dns_file.txt: the list of PCAP file paths. """.format(prog_name=PATH)
    
    print(USAGE, file=sys.stderr) if is_error else print(USAGE)
    exit(is_error)

local_ip_block = '2001:470:8863:1aba'

def hostname_extract(infiles, dev_name):
    ip_host = {} # dictionary of destination IP to hostname
    domain_list = set()
    for in_pcap in infiles:
        # file contains hosts and ips in format [hostname]\t[ip,ip2,ip3...]
        hosts = str(os.popen("tshark -r %s -Y \"dns.flags.response && not mdns\" -T fields -e dns.qry.name -e dns.qry.type -e dns.a -e dns.aaaa"
                            % in_pcap).read()).splitlines()
        
        
        for line in hosts: # load ip_host
            line = line.split("\t") # host_name, dns_type, ips
            if line[0].startswith('192.168.') or line[0].startswith(local_ip_block) \
                or 'in-addr.arpa' in line[0] or '.local' in line[0]:
                continue
            dns_type = line[1]
            if dns_type == '28':
                ips = line[3].split(",")
            else:
                # print(line)
                ips = line[2].split(",")
            domain = line[0].lower()
            if domain[-1] == '.':
                domain = domain[:-1]

            domain_list.add(domain)
            for ip in ips:

                ip_host[ip] = domain

        tls_hosts = str(os.popen("tshark -r %s -Y \"tls.handshake.extensions_server_name\" -T fields -e tls.handshake.extensions_server_name -e ip.dst"
                            % in_pcap).read()).splitlines()
        
        for line in tls_hosts:
            line = line.split("\t")
            if domain.startswith('192.168.') or 'in-addr.arpa' in line[0] or '.local' in line[0]:
                continue
            domain = line[0].lower()
            if domain[-1] == '.':
                domain = domain[:-1]

            domain_list.add(domain)
            ips = line[1].split(",")
            for ip in ips:
                ip_host[ip] = domain
    print("Extraction done: ", dev_name) # , ip_host

    return ip_host, domain_list

def worker(dev, dns_files):
    return hostname_extract(dns_files[dev], dev)
                            
def main():
    [ print_usage(0) for arg in sys.argv if arg in ("-h", "--help") ]

    print("Running %s..." % sys.argv[0])

    in_txt = sys.argv[1]
    out_dir = sys.argv[2]
    errors = False

    if errors:
        print_usage(1)

    print("Input file located in: %s\n" % (in_txt))


    dns_files = {}

    with open(in_txt, "r") as f:
        for pcap in f:
            pcap = pcap.strip()
            if not pcap.endswith(".pcap"):
                continue
            elif not os.path.isfile(pcap):
                print(pcap)
                exit(1)
            elif not os.access(pcap, os.R_OK):
                print(pcap)
                exit(1)
            else:

                dir_name = os.path.dirname(pcap)
                dev_name = os.path.basename(pcap).split('.')[0]
                # if dev_name != 'ring-doorbell':
                #     continue

                ## only accept merged file, not origial pcap file
                # if os.path.basename(pcap).startswith('2021'):
                #     continue
                
                # print(pcap)
                if dev_name in dns_files:
                    dns_files[dev_name].append(pcap)
                else:
                    dns_files[dev_name] = [pcap]

    print(dns_files)
    ip_hosts_all = {}
    domain_list_all = {}
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_dev = {executor.submit(worker, dev, dns_files): dev for dev in dns_files.keys()}
        for future in concurrent.futures.as_completed(future_to_dev):
            dev = future_to_dev[future]
            result = future.result()
            if result is not None:
                ip_host_res, domain_list = result
                try:
                    ip_hosts_all[dev] = ip_host_res # dict
                    domain_list_all[dev] = domain_list  # set
                except Exception as exc:
                    print(f'{dev} generated an exception: {exc}')

    
    # output dir 
    # out_dir = 'output'
    if not os.path.exists(out_dir):
        os.system(f'mkdir -pv {out_dir}')

    model_file = f"{out_dir}/{os.path.basename(in_txt).split('.')[0]}_ip_hosts_all.model"
    
    pickle.dump(ip_hosts_all, open(model_file, 'wb'))
    pickle.dump(domain_list_all, open(f"{out_dir}/{os.path.basename(in_txt).split('.')[0]}_domain_list_all.model", 'wb'))
    for dev in domain_list_all:
        domain_list_all[dev] = list(domain_list_all[dev])
    json.dump(domain_list_all, open(f"{out_dir}/{os.path.basename(in_txt).split('.')[0]}_domain_list_all.json", 'w'), indent=4)

if __name__ == "__main__":
    main()

