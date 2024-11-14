from src.helper import *
from src.protocols import *
from src.helper.utils import *
from src.helper.db_query import * 
import matplotlib.pyplot as plt
import matplotlib
import pickle

destination_analysis_path = '/home/hutr/iot-ipv6-project'

class Deivce:
    def __init__(self, name:str, mac:str):
        self.name = name
        self.mac = mac
        self.category = None
        self.ipv6 = []
        self.ipv4 = []
        self.dns = []
        self.dhcp = []
        self.icmp = []
        self.udp = []
        self.tcp = []

    def __str__(self):
        return f"{self.name} {self.mac} {self.category}"
    
    def __repr__(self):
        return f"Device({self.name},{self.mac})"
    
def save_json(data, file_path):
    with open(file_path, 'w') as f:
        json.dump(data, f, indent=4)

def find_eui64_address(device, ips):
    mac_address = mac_dict[device]
    eui64_address = set()
    for ipv6_address in ips:
        if address.is_eui64_address(mac_address, ipv6_address):
            eui64_address.add(ipv6_address)
    return eui64_address

def dig_x(ip):
    domain_name = ''
    # dig - x ip +short
    command = ["dig", "-x", ip, "+short"]
    process = Popen(command, stdout=PIPE, stderr=PIPE)
    # Get output. Give warning message if any
    out, err = process.communicate()
    # print(out.decode('utf-8').split('\n'))
    return out.decode('utf-8').split('\n')[0]

def print_usage(is_error:bool) -> None:
    # TODO
    print(ANALYSIS_USAGE, file=sys.stderr) if is_error else print(ANALYSIS_USAGE)
    exit(is_error)


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

def arugment_parser():
    parser = argparse.ArgumentParser(description="IPv6 data analysis tool")
    parser.add_argument("in_dir")
    parser.add_argument("out_dir")
    parser.add_argument("-e", "--experiment", dest="experiment_name", default='exp2', help="experiment name")
    parser.add_argument("-t", "--test", dest="data_analysis_name", default='test', help="data analysis name")
    args = parser.parse_args()
    
    in_dir = args.in_dir
    out_dir = args.out_dir
    experiment_name = args.experiment_name
    data_analysis_name = args.data_analysis_name
    
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
    
    return in_dir, out_dir, experiment_name, data_analysis_name
