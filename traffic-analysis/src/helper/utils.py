import os
import sys
import json
import argparse
from collections import Counter
from copy import deepcopy
import csv
import time
import datetime
import re
from scapy.all import *
from sqlite3 import IntegrityError
import sqlite3
import pandas as pd
import threading
import ipaddress
import matplotlib.pyplot as plt
import numpy as np
import traceback
from subprocess import Popen, PIPE

GLOBAL_IPV6_PREFIX = '2001:470:8863:1aba'
MAC_ADDRESS_FILE = 'devices-ipv6-mac.txt'
# MAC_ADDRESS_FILE = './devices.txt'  # mac address file with ALL mac address to device name mappings. Not only devices, but phones
IP_ADDRESS_FILE = 'helper/ip_dict.txt'
ROUTER_MAC = '36:22:7b:87:51:6f'
DNS_ADDRESS = '2001:4860:4860::8888'
DNS_ADDRESS_2 = '2001:4860:4860::8844'
ANALYSIS_USAGE = """
USAGE: 
"""

INVAL = """
"""
NO_PERM = """
"""

WRONG_EXT = """
"""

global_lock = threading.Lock()

def output_file_generator(out_dir:str, basename:str, device:str) -> str:
    tmp_dir = os.path.join(out_dir, basename)
    if not os.path.exists(tmp_dir):
        os.system('mkdir -pv %s' % tmp_dir)
    output_file = os.path.join(tmp_dir, device + '.txt') # Output file
    return output_file

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
                # mac_split = tmp_mac.split(':')
                # for i in range(len(mac_split)):
                #     if len(mac_split[i]) != 2:
                #         mac_split[i]='0'+mac_split[i]
                # tmp_mac = ':'.join(mac_split)
            mac_dic[tmp_device] = tmp_mac
    # print(mac_dic)
    return mac_dic

def merge_pcap(new_pcap_dir, pcap_filter, pcap_list):
    print('merge pcap...')
    output_pcap = os.path.join(new_pcap_dir, pcap_filter+'.pcap')
    tmp_list = []
    # print(pcap_list)
    for i in pcap_list:
        tmp_list.append(os.path.join(new_pcap_dir, i))
    input_pcaps = ' '.join(tmp_list)

    os.system('mergecap -w %s %s' % (output_pcap, input_pcaps))
    for i in tmp_list:
        os.system('rm %s' % i)

    return 0

def dig_x(ip):
    domain_name = ''
    # dig - x ip +short
    command = ["dig", "-x", ip, "+short"]
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    # Get output. Give warning message if any
    out, err = process.communicate()
    # print(out.decode('utf-8').split('\n'))
    return out.decode('utf-8').split('\n')[0]