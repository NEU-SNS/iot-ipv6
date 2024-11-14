# Port Scanning Experiments

This module uses Nmap for port scanning. The script is adapted from our previous project: [IoT-LAN](https://github.com/Android-Observatory/IoT-LAN).

### Usage
Run the following commands to perform port scans:

```bash
# TCP scan for all ports on IPv4 addresses
sudo python3 nmap_scan.py -a "-p 1-65535 -sS -sV -T4 --reason" -f device_ipv4_address.json

# TCP scan for all ports on IPv6 addresses
sudo python3 nmap_scan.py -a "-p 1-65535 -sS -sV -T4 --reason -6" -f device_ipv6_address.json

# UDP scan for common ports on IPv4 addresses
sudo python3 nmap_scan.py -a "-p 1-1024 -sU -sV -T4 --open --reason" -f device_ipv4_address.json

# UDP scan for common ports on IPv6 addresses
sudo python3 nmap_scan.py -a "-p 1-1024 -sU -sV -T4 --open --reason -6" -f device_ipv6_address.json
```

`device_ipvX_address.json` contains a list of IPv4 or IPv6 addresses, where each entry maps the device name (key) to its address (value).