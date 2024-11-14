from nmap_tool import Tool
import xmltodict
import csv
import os
import json
import time
import re
import concurrent.futures
import logging
import sys

def setup_logger(logger_name, logger_file, level=logging.DEBUG):
    logger = logging.getLogger(logger_name)
    logging.basicConfig(filename=logger_file, filemode='a+', level=level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)


    logger.info("----------------------------------")
    logger.info("---|| IoTv6 Project Analysis ||---")
    logger.info("----------------------------------")
    return logger

def sanitize_filename(filename):
    # Replace invalid characters with an underscore
    return re.sub(r'[\\/:"*?<>|]+', '_', filename)
def dicttocsv(out_dict, csv_writer):
    scanner = out_dict['nmaprun']['@scanner']
    args = out_dict['nmaprun']['@args']
    start_time = out_dict['nmaprun']['@start']
    start_time_str = out_dict['nmaprun']['@startstr']
    version = out_dict['nmaprun']['@version']
    xmloutputversion = out_dict['nmaprun']['@xmloutputversion']
    verbose = out_dict['nmaprun']['verbose']['@level']
    hosts_up = out_dict['nmaprun']['runstats']['hosts']['@up'],
    hosts_down = out_dict['nmaprun']['runstats']['hosts']['@down'],
    hosts_total = out_dict['nmaprun']['runstats']['hosts']['@total']
    
    hosts = out_dict['nmaprun']['host']
    if not isinstance(hosts, list):
        hosts = [hosts]
    for host in hosts:
        address = host['address']
        ip_addr = ''
        mac_addr = ''
        vendor = ''
        if isinstance(address, list):
            for addr_item in address:
                if addr_item['@addrtype'] == 'ipv4':
                    ip_addr = addr_item['@addr']
                elif addr_item['@addrtype'] == 'mac':
                    mac_addr = addr_item['@addr']
                    vendor = addr_item.get('@vendor', '')
        else:
            ip_addr = address['@addr']


        ports_data = host.get('ports', {})
        if 'port' in ports_data:
            ports = ports_data['port']
            if not isinstance(ports, list):
                ports = [ports]

            for port in ports:
                protocol = port['@protocol']
                port_id = port['@portid']
                state = port['state']['@state']
                reason = port['state']['@reason']
                service = 'unknown'
                service_version = 'unknown'
                if 'service' in port:
                    service = port['service']['@name']
                    if '@product' in port['service']:
                        service_version = port['service']['@product'] + ' ' + port['service'].get('@version', 'unknown')

                row = {
                    'scanner': scanner,
                    'args': args,
                    'start_time': start_time,
                    'start_time_str': start_time_str,
                    'version': version,
                    'xmloutputversion': xmloutputversion,
                    'verbose': verbose,
                    'hosts_up': hosts_up,
                    'hosts_down': hosts_down,
                    'hosts_total': hosts_total,
                    'ip_addr': ip_addr,
                    'mac_addr': mac_addr,
                    'vendor': vendor,
                    'protocol': protocol,
                    'port_id': port_id,
                    'state': state,
                    'reason': reason,
                    'service': service,
                    'service_version': service_version,
                }
                csv_writer.writerow(row)


def dicttocsv_all(out_dict_all, csv_writer):
    for addr, out_dict in out_dict_all.items():
        # print(addr, out_dict)
        scanner = out_dict['nmaprun']['@scanner']
        args = out_dict['nmaprun']['@args']
        start_time = out_dict['nmaprun']['@start']
        start_time_str = out_dict['nmaprun']['@startstr']
        version = out_dict['nmaprun']['@version']
        xmloutputversion = out_dict['nmaprun']['@xmloutputversion']
        verbose = out_dict['nmaprun']['verbose']['@level']
        hosts_up = out_dict['nmaprun']['runstats']['hosts']['@up'],
        hosts_down = out_dict['nmaprun']['runstats']['hosts']['@down'],
        hosts_total = out_dict['nmaprun']['runstats']['hosts']['@total']
        if 'host' not in out_dict['nmaprun']:
            continue
        hosts = out_dict['nmaprun']['host']
        if not isinstance(hosts, list):
            hosts = [hosts]
        for host in hosts:
            address = host['address']
            ip_addr = ''
            mac_addr = ''
            vendor = ''
            if isinstance(address, list):
                for addr_item in address:
                    if addr_item['@addrtype'] == 'ipv4':
                        ip_addr = addr_item['@addr']
                    elif addr_item['@addrtype'] == 'mac':
                        mac_addr = addr_item['@addr']
                        vendor = addr_item.get('@vendor', '')
            else:
                ip_addr = address['@addr']


            ports_data = host.get('ports', {})
            if 'port' in ports_data:
                ports = ports_data['port']
                if not isinstance(ports, list):
                    ports = [ports]

                for port in ports:
                    protocol = port['@protocol']
                    port_id = port['@portid']
                    state = port['state']['@state']
                    reason = port['state']['@reason']
                    service = 'unknown'
                    service_version = 'unknown'
                    if 'service' in port:
                        service = port['service']['@name']
                        if '@product' in port['service']:
                            service_version = port['service']['@product'] + ' ' + port['service'].get('@version', 'unknown')

                    row = {
                        'scanner': scanner,
                        'args': args,
                        'start_time': start_time,
                        'start_time_str': start_time_str,
                        'version': version,
                        'xmloutputversion': xmloutputversion,
                        'verbose': verbose,
                        'hosts_up': hosts_up,
                        'hosts_down': hosts_down,
                        'hosts_total': hosts_total,
                        'ip_addr': ip_addr,
                        'mac_addr': mac_addr,
                        'vendor': vendor,
                        'protocol': protocol,
                        'port_id': port_id,
                        'state': state,
                        'reason': reason,
                        'service': service,
                        'service_version': service_version,
                    }
                    csv_writer.writerow(row)


class Nmap(Tool):
    """
    Nmap tool execution class.
    """

    def __init__(self, path="nmap", default_args="-oX -"):
        """
        Initialize the Nmap Tool object

        Args:
            path(str): The full path (or the name) of nmap. Default
                is "nmap"
            default_args(str): Any default args that should always be
                part of the nmap arguments. Default is xml output argument
                "-oX -".
        """
        self.logger = logging.getLogger('IoTv6')
        super().__init__(path, default_args=default_args)

    def read_input_file(self, input_file):
        with open(input_file, 'r') as f:
            addr_dict = json.load(f)
        return addr_dict
    
    def run_command(self, addr, args, timeout=None):
        try:
            out, err = self.run(f"{args} {addr}", timeout=timeout)
            err = err.decode() if err else None
            if not out:
                if not err:
                    self.logger.error(f"Error running nmap command: {args} {addr}")
            else:
                return out
        except:
            return None
    
    def run_xmltodict_output(self, args, input_file, timeout=None, csv_file=None):
        """
        Run the command as a child with the specified arguments
        and return the output as a dict along with the error if any.
        The xml to dict format is generated by xmltodict package which
        is based on the format specified here -
        https://www.xml.com/pub/a/2006/05/31/converting-between-xml-and-json.html

        Args:
            args(str): The arguments to be supplied to nmap.
            timeout(int): The timeout in seconds while waiting
                for the output. Default is None. For details check
                subprocess.Popen() timeout argument.
        Returns:
            tuple of dict,str: Tuple of xml output converted to dict
                and error converted from bytes to str.
                (stdout,stderr)
        """
        logger = logging.getLogger("nmap_scan")
        addr_dict = self.read_input_file(input_file)
        tmp_out = []
        tmp_out_dict_list = []
        tmp_out_dict = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:

            # future_to_addr = {executor.submit(self.run_command, addr, args, timeout): addr for device in addr_dict.keys() for addr in addr_dict[device]}
            
            # Create a dictionary that maps futures to addresses
            future_to_addr = {}
            start_time = time.time()
            for device in addr_dict.keys():
                if len(addr_dict[device])==0:
                    continue
                logger.info(f'Device: {device}')  # Print the device name when tasks for it are submitted
                for addr in addr_dict[device]:
                    future = executor.submit(self.run_command, addr, args, timeout)
                    future_to_addr[future] = addr
            for future in concurrent.futures.as_completed(future_to_addr):
                out = future.result()
                addr = future_to_addr[future]
                if out and '-oX' in self.default_args:
                    try:
                        out_dict = xmltodict.parse(out, dict_constructor=dict)
                    except Exception as e:
                        logger.error(f'{addr} xmltodict error: {e}')
                        continue
                    tmp_out_dict[addr] = out_dict
                    logger.info(f'Finish {addr} --- {time.time()-start_time}')
                    tmp_name = sanitize_filename(csv_file.split('.csv')[0])
                    with open(f'output/tmp/{addr}_{tmp_name}.json', 'w') as ff:
                        json.dump(tmp_out_dict, ff, indent=4)
                elif out:
                    tmp_list = []
                    for line in filter(None, out.decode('utf-8').split('\n')):
                        """
                        Nmap scan report for fe80::86fc:e6ff:fe32:e030
                        Host is up, received nd-response (0.016s latency).
                        Not shown: 60020 closed ports
                        Reason: 60020 resets
                        PORT      STATE    SERVICE REASON      VERSION
                        8907/tcp  filtered unknown no-response
                        21046/tcp filtered unknown no-response
                        48341/tcp filtered unknown no-response
                        54648/tcp filtered unknown no-response
                        MAC Address: 84:FC:E6:32:E0:30 (Unknown)
                        """
                        if '/tcp' or '/udp' or '/ip' in line:
                            tmp_list.append(line)
                    tmp_out_dict[addr] = tmp_list
        
            for addr in tmp_out_dict:
                print(addr, tmp_out_dict[addr], '\n')
            # print('-----printing json-----')
            if csv_file:
                dump_filename = 'output/dict_dump_' + sanitize_filename(csv_file.split('.csv')[0]) + '.json'
                with open(dump_filename, 'w') as fp:
                    json.dump(tmp_out_dict, fp, indent=4)

                with open(os.path.join('output', sanitize_filename(csv_file)), mode='w') as f:
                    writer = csv.DictWriter(f, fieldnames=['scanner', 'ip_addr', 'mac_addr', 'vendor', 'args', 'start_time', 'start_time_str', 'version', 'xmloutputversion', 'verbose', 'hosts_up', 'hosts_down', 'hosts_total',  'protocol', 'port_id', 'state', 'reason', 'service', 'service_version'])
                    writer.writeheader()
                    dicttocsv_all(tmp_out_dict, writer)

        return (None)