# Destination Analysis Scripts
This module provides scripts for extracting IP-domain mappings and identifying destination organizations.

* ip-domain-mappings.py: extracts mappings from DNS answers and TLS client hello messages. 
* merge_dict.py: merges ip-domain dict from all 6 experiments
* get_ipv4_desination.py: gets IPv4 destination contacted by each devices 
* getorg.py: maps destination domain names to their respective organizations. A sample input file is provided in `sample_getorg_input`.
### Usage
Run each script as shown below:

```bash
    python3 ip-domain-mappings.py input/exp234.txt
    python3 ip-domain-mappings.py input/exp56.txt
    python3 ip-domain-mappings.py input/exp1.txt

    python3 merge_dict.py

    python3 get_ipv4_destination.py input/exp1_data.txt output

    python3 getorg.py
```
