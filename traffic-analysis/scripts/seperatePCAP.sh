#!/bin/bash

# Check if the correct number of arguments are provided
if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <pcap_directory> <output_directory> [<protocol_filter>]"
    exit 1
fi

# First argument: Directory containing PCAP files
pcap_directory="$1"

# Second argument: Output directory for merged PCAP files
output_directory="$2"

# Third argument: Whether to filter by protocol, optional with default "no"
filter="${3:-}"

# Create the output directory if it does not exist
mkdir -p "$output_directory"

# File containing MAC addresses and device names
device_file="devices-ipv6.txt"
device_file="full-working-2024-devcies.txt"
mac_device_file="devices.txt"

temp_directory="${output_directory}/temp"
mkdir -p "$temp_directory"

declare -A device_mac_map

while IFS= read -r line
do
    device=$(echo $line | cut -d ' ' -f 2)
    mac=$(echo $line | cut -d ' ' -f 1)
    device_mac_map["$device"]=$mac
done < "$mac_device_file"

# Loop through each PCAP file in the directory
for pcap in $pcap_directory/*.pcap*; do
    (
        echo "Processing file: $pcap"
        # Extract a unique identifier from the PCAP filename, e.g., using filename or timestamp
        pcap_id=$(echo "$pcap" | cut -d '.' -f 1)
        id=$(echo "$pcap" | grep -oP 'ipv6_split_\K\d+(?=_)') # grep -oP 'pcap\K\d+$')
        pcap_id="${pcap_id}-${id}"

        # Read each line in the device file
        while read -r device_name; do
            # if [ "$device_name" == "labelprinter" ]; then
            #     echo "$device_name"
            # Get the MAC address for this device from the dictionary
            mac_address=${device_mac_map["$device_name"]}
            # Adjusted filename to include the original PCAP identifier
            output_filename="${temp_directory}/${device_name}_${id}.pcap"
            # Filter the PCAP by MAC address and save with device name
            # Check if IPv6 filtering is enabled and adjust the base filter
            if [ -n "$filter" ]; then
                tshark -r "$pcap" -w "$output_filename" -Y "(eth.src==$mac_address || eth.dst==$mac_address) && $filter"
            else
                tshark -r "$pcap" -w "$output_filename" -Y "(eth.src==$mac_address || eth.dst==$mac_address)"
            fi
            # fi
        done < "$device_file"
    ) &
done
wait

# Merge files for each device
while read -r device_name; do
    # if [ "$device_name" == "magichome-strip" ]; then
    #     (
    # Pattern to match all files for this device
    pattern="${temp_directory}/${device_name}_*.pcap"
    
    # Final output filename
    final_output="${output_directory}/${device_name}.pcap"
    
    echo "Merging files for device: $device_name"
    mergecap -w "$final_output" $pattern
    #     ) &
    # fi
done < "$device_file"

# Optionally, clean up the temporary directory
rm -rf "$temp_directory"

echo "Processing complete."
