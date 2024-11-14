#!/bin/bash

# Directory to search in
search_directory="$1"

# Find and delete PCAP files of exactly 144 bytes
find "$search_directory" -type f -name '*.pcap' -size 144c -print0 | xargs -0 rm -v

echo "Deletion complete."
