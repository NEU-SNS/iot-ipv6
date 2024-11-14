#!bin/bash

# Define paths
path_to_dataset="~/2024-datasets"
path_to_output="~/iot-ipv6-output"

# Run traffic analysis with specified paths
nohup python3 -u traffic_analysis.py "$path_to_dataset/exp2/" "$path_to_output/results-exp2/" -e exp2 > nohup_out/exp2nohup.out &
nohup python3 -u traffic_analysis.py "$path_to_dataset/exp3/" "$path_to_output/results-exp3/" -e exp3 > nohup_out/exp3nohup.out &
nohup python3 -u traffic_analysis.py "$path_to_dataset/exp4/" "$path_to_output/results-exp4/" -e exp4 > nohup_out/exp4nohup.out &

nohup python3 -u traffic_analysis.py "$path_to_dataset/exp5/" "$path_to_output/results-exp5/" -e exp5 > nohup_out/exp5.out &
nohup python3 -u traffic_analysis.py "$path_to_dataset/exp6/" "$path_to_output/results-exp6/" -e exp6 > nohup_out/exp6.out &