#!/bin/bash

# Check if the correct number of arguments are provided
if [ "$#" -lt 3 ]; then
    echo "Usage: $0 <pcap_directory> <protocol> <output_directory>"
    exit 1
fi

# First argument: Directory containing PCAP files
pcap_directory="$1"

# Second argument: tshark filter
tshark_filter="$2"

# Third argument: Output directory for merged PCAP files
output_directory="$3"


# Create the output directory if it does not exist
mkdir -p "$output_directory"

# temp_directory="${output_directory}/${tshark_filter}"
# mkdir -p "$temp_directory"

# Loop through each PCAP file in the directory
for pcap in "$pcap_directory"/*.pcap; do
    echo "Processing file: $pcap"
    # Extract a unique identifier from the PCAP filename, e.g., using filename or timestamp
    device_name=$(basename "$pcap" .pcap)

    # Adjusted filename to include the original PCAP identifier
    output_filename="${output_directory}/${device_name}.pcap"

    echo "Filtering $tshark_filter for device: $device_name"
    tshark -r "$pcap" -w "$output_filename" -Y "$tshark_filter" || { echo "tshark processing failed for $pcap"; continue; }
done

echo "Processing complete."
