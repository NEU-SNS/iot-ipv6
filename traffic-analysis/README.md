# IoTv6 Proejct Analysis Scripts 
This directory contains scripts and modules for traffic analysis and data analysis. 

## Traffic Analysis

### Files: 
* devices-ipv6.txt: List of devices names
* devices-ipv6-mac.txt: List of device names and corresponding MAC addresses.
* ipv6-device-category.csv: Categories and manufacturers of devices.
* traffic_analysis.py: Main script for traffic analysis.
* traffic_analysis.sh: One-step shell script to run traffic analysis.
* data_analysis.py: Script for analyzing the results of traffic analysis.
* data_analysis.sh: One-step shell script to generate all data analysis results.
* scripts/: Directory containing dataset preprocessing scripts.
* src/: Directory containing Python modules and functions.


### Preprocessing (scripts/)
* script/seperatePCAP.sh: **Note: This script is not needed if using our preprocessed datasets.** Labels traffic based on MAC address and creates separate PCAP files for each device. Optionally applies a tshark filter.
* script/merge-twomac.sh: merges data for devices with both wireless and wired MAC addresses.
* script/protocol-filter.sh: Filters traffic using a tshark filter.
* script/rm-empyt.sh: Removes empty PCAP files.
* script/get_device_year.py: Get device purchase date in device_year.json. 

### Modules (src/)
* helper
    * A module to distinguish between IPv6 address type, identify EUI-64 based address, logger setup, etc.
* data_analysis
    * Analysis scripts
* protocols
    * Traffic parsing

### Traffic processing and analysis
* one-step script:
```
./traffic_analysis.sh
```
* traffic_analysis.py:
    * input: PCAPs
    * analysis: extract features and statistics from PCAPs
    * output: SQLite database and CSV files
```
python3 traffic_analysis.py dataset_dir/exp2/ output_dir/exp2 -e exp2
```

### Data analysis
* one-step script:
```
./data_analysis.sh
```

```
python3 data_analysis.py input_dir/exp2 result_dir/exp2 -e exp2 -t apr22 
python3 data_analysis.py input_dir result_dir -e merged -t apr22 
python3 data_analysis.py result_dir result_dir/diff -e diff -t apr22 
python3 data_analysis.py result_dir result_dir/exp2 -e manufacturer-exp2 -t apr22 
```

