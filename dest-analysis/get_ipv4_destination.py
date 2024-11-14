import sys
import os
import whois
import ipaddress
import json
import numpy as np
from subprocess import Popen, PIPE
import concurrent.futures
import pickle

"""

Get destination hostname or device name from pcap file

"""
# cdn_keywords = ['akamai', 'cloudflare', 'amazonaws' , 'cloudfront', 'devices.a2z.com', '1e100.net', 'node.netflix.net', 'nflxso.net', 'nflxvideo.net']
def dig_x(ip):
    domain_name = ''
    # dig - x ip +short
    command = ["dig", "-x", ip, "+short"]
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    # Get output. Give warning message if any
    out, err = process.communicate()
    # print(out.decode('utf-8').split('\n'))
    return out.decode('utf-8').split('\n')[0]

#is_error is either 0 or 1
def print_usage(is_error):
    exit(is_error)


mac_dic = {}
# MAC_ADDRESS_FILE = '/home/hutr/iot-ipv6-project/iot-ipv6/devices.txt'
MAC_ADDRESS_FILE = 'devices-ipv6-mac.txt'
# DEVICE_FILE = '/home/hutr/iot-ipv6-project/iot-ipv6/devices-ipv6.txt'

def validate_ip_address(address):
    try:
        ip = ipaddress.ip_address(address)
        # print("IP address {} is valid. The object returned is {}".format(address, ip))
        return True
    except ValueError:
        # print("IP address {} is not valid".format(address)) 
        return False


def is_local(ip_src, ip_dst):
    is_local = False
    try:
        is_local = (ipaddress.ip_address(ip_src).is_private and ipaddress.ip_address(ip_dst).is_private
                ) or (ipaddress.ip_address(ip_src).is_private and (ip_dst=="129.10.227.248" or ip_dst=="129.10.227.207")
                ) or (ipaddress.ip_address(ip_dst).is_private and (ip_src=="129.10.227.248" or ip_src=="129.10.227.207"))
    except:
        print('Error:', ip_src, ip_dst)
        return 1
    return is_local

def extract_host_new(my_ip, ip_dst, eth_dst, ip_host, inverse_mac_dic):
    """
    Extracts the host information based on the given IP address.

    Args:
        my_ip (str): The IP address of the local machine.
        ip_dst (str): The destination IP address.
        ip_host (dict): A dictionary containing IP addresses and their corresponding host information. {IP: Hostname}

    Returns:
        str: The extracted host information.
    """

    host = 0

    # local traffic
    if is_local(my_ip, ip_dst):
        if eth_dst in inverse_mac_dic:
            host = inverse_mac_dic[eth_dst]
        else:
            host = ""
        local = 1
        return host, local
    #  ip_dst is in ip_host dictionary
    elif ip_dst in ip_host: 

        host = ip_host[ip_dst]

    
    #  ip_dst is NOT in ip_host dictionary
    else:
        # use dig -x to extract hostname
        try:
            dig = dig_x(ip_dst)
            if dig is None or dig == '':
                host = ip_dst

            else:
                host = ip_host[ip_dst] = dig.lower() #  = ip_host[ip_dst] 
                # print('----------WHOIS:', host)

        except Exception as e:
            print('Exception: ',str(e))
            host = ip_dst

    return host, 0



def extract_pcap(in_pcap, out_txt, dev_name, ip_host):
    # Note: PcapReader from scapy and pyshark seems to be slower than using tshark    
    out_dict = {'Global': set(), 'Local': set()}
    command = ["tshark", "-r", in_pcap, 
                "-Y", "(tcp || (udp && !dns && !dhcp)) && (eth.dst.ig == 0)",
                # "not tcp.analysis.duplicate_ack and not tcp.analysis.retransmission and not tcp.analysis.fast_retransmission",
                "-Tfields",
                "-e", "frame.number",
                "-e", "eth.src",
                "-e", "eth.dst",
                "-e", "ip.src",
                "-e", "ip.dst",
                "-e", "ip.proto",
                "-e", "tcp.srcport",
                "-e", "udp.srcport",
                "-e", "tcp.dstport",
                "-e", "udp.dstport"
                ] # tcp.analysis.flags
                # "-e", "ip.proto" # it returns transport layer protocol code. 
    result = []
    # Call Tshark on packets
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    # Get output. Give warning message if any
    out, err = process.communicate()
    if err:
        print("Error reading file: '{}'".format(err.decode('utf-8')))


    # Parsing packets
    my_device_mac =  mac_dic[dev_name]
    inverse_mac_dic = {v: k for k, v in mac_dic.items()}
    # print('Processing')
    
    for packet in filter(None, out.decode('utf-8').split('\n')):
        packet = np.array(packet.split())
        if len(packet) > 8:
            packet = np.append(packet[:8], ' '.join(packet[8:]))
        if len(packet) < 8:
            # print('Length incorrect! ', packet)
            continue
        eth_src = packet[1]
        eth_dst = packet[2]
        ip_src = packet[3]
        ip_dst = packet[4]  # desintation host -> -e ip.dst
        ip_proto = packet[5]
        srcport = packet[6]
        dstport = packet[7]
        
        
        if validate_ip_address(ip_src)==False or validate_ip_address(ip_dst)==False:
            continue

        if my_device_mac == eth_dst:  # inbound traffic
            continue
            # host = extract_host_new(ip_dst, ip_src, ip_host, count_dic)
        else:   # extract hostname for all outbound traffic
            host, local_dst = extract_host_new(ip_src, ip_dst, eth_dst, ip_host, inverse_mac_dic)
        
        if len(host) == 0:
            continue
        host = host.lower()
        if local_dst == 1:
            out_dict['Local'].add(host)
        else:
            if host[-1] == '.':
                host = host[:-1]
            # for cdn in cdn_keywords:
            #     if cdn in host:
            #         host = '.'.join(host.split('.')[1:])
            out_dict['Global'].add(host)
        packet = np.append(packet,host) #append host as last column of output
        
        result.append(packet)
    result = np.asarray(result)
    if len(result) == 0:
        print('len(result) == 0')
        return out_dict
    
    return out_dict


def run(file, out_dir, ip_hosts):
    # print("number of files:",len(files))
    out_dict_all = {'Global': {}, 'Local': {}}
    
    f = file
    # parse pcap filename
    # dir_name = os.path.dirname(f)
    
    dev_name = os.path.basename(f).split('.')[0]

    out_txt = os.path.join(out_dir, os.path.basename(f)[:-4] + "txt")
    # nothing happens if output file exists
    print(dev_name, out_txt)

    ip_host = ip_hosts[dev_name]
    out_dict = extract_pcap(f, out_txt, dev_name, ip_host)

    out_dict_all['Global'][dev_name] = out_dict['Global']
    out_dict_all['Local'][dev_name] = out_dict['Local']
    return out_dict_all

def expand_mac_address(mac_address:str) -> str:
    octets = mac_address.split(":")
    octets = [octet.zfill(2).lower() for octet in octets]
    return ":".join(octets)
    
    
def read_mac_address() -> dict:
    mac_file = MAC_ADDRESS_FILE
    mac_dic = {}
    with open(mac_file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line.startswith(' ') or line.startswith('/n'):
                continue
            # print(line[:-1])
            tmp_mac, tmp_device = line[:-1].split(' ')
            if len(tmp_mac) != 17:
                tmp_mac = expand_mac_address(tmp_mac)
            mac_dic[tmp_device] = tmp_mac
            # mac_dic[tmp_mac] = tmp_device
    # print(mac_dic)
    return mac_dic

def main():
    global mac_dic
    [ print_usage(0) for arg in sys.argv if arg in ("-h", "--help") ]

    print("Running %s..." % sys.argv[0])

    #error checking
    #check for 2 or 3 arguments
    if len(sys.argv) != 3:
        print_usage(1)

    in_txt = sys.argv[1]
    out_dir = sys.argv[2]



    # if errors:
    #     print_usage(1)
    #end error checking
    mac_dic = read_mac_address()

    in_files = []


    with open(in_txt, "r") as f:
        for pcap in f:
            pcap = pcap.strip()
            if not pcap.endswith(".pcap"):
                continue
            elif not os.path.isfile(pcap):
                continue
            elif not os.access(pcap, os.R_OK):
                continue
            else:
                in_files.append(pcap)
                # dir_name = os.path.dirname(pcap)    
                # dev_name = os.path.basename(pcap).split('.')[0]
                # # if dev_name != 'google-nest-mini1' and dev_name != 'wyze-cam': # gosund-bulb1, echoflex1
                # #     continue

                # index = dev_proc[dev_name]
                # in_files[index % num_proc].append(pcap)
                # index += 1

                

    ip_hosts_all = {}


    model_file = 'output/exp1_ip_hosts_all.model'
    ip_hosts_all = pickle.load(open(model_file, 'rb'))
    
    
    out_dir_all = {'Global': {}, 'Local': {}}
    # Create a ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Submit tasks to the executor
        futures = {executor.submit(run, file, out_dir, ip_hosts_all): file for file in in_files}

        # Wait for all tasks to complete
        for future in concurrent.futures.as_completed(futures):
            try:
                # Get the result of the task
                out_dict_tmp = future.result()
                for key in out_dict_tmp:
                    if key in out_dir_all:
                        out_dir_all[key].update(out_dict_tmp[key])
                    else:
                        print('Error: ', key, futures[future])
            except Exception as exc:
                print(f'A thread generated an exception: {exc}')
                
    with open('output/exp1_destination_name_dict.pkl', 'wb') as f:
        pickle.dump(out_dir_all, f)
    # output to json
    for device in out_dir_all['Global']:
        out_dir_all['Global'][device] = list(out_dir_all['Global'][device])
    for device in out_dir_all['Local']:
        out_dir_all['Local'][device] = list(out_dir_all['Local'][device])
    with open('output/exp1_destination_name_dict.json', 'w') as f:
        json.dump(out_dir_all, f, indent=4)
            
if __name__ == "__main__":
    main()

