#!bin/bash
# Define paths
path_to_input="~/iot-ipv6-output"
path_to_output="~/analysis-results"

python3 data_analysis.py "$path_to_input/results-exp2" "$path_to_output/may15/exp2" -e exp2 -t may15
python3 data_analysis.py "$path_to_input/results-exp3" "$path_to_output/may15/exp3" -e exp3 -t may15
python3 data_analysis.py "$path_to_input/results-exp4" "$path_to_output/may15/exp4" -e exp4 -t may15
python3 data_analysis.py "$path_to_input" "$path_to_output/may15/" -e merged -t may15

python3 data_analysis.py "$path_to_input/results-exp5-ipv6dns/" "$path_to_output/may15/exp5-ipv6dns" -e exp5-ipv6dns -t may15
python3 data_analysis.py "$path_to_input/results-exp6-ipv6dns/" "$path_to_output/may15/exp6-ipv6dns" -e exp6-ipv6dns -t may15
python3 data_analysis.py "$path_to_input" "$path_to_output/may15/" -e merged-hybrid -t may15
python3 data_analysis.py "$path_to_input" "$path_to_output/may15/" -e merged-all -t may15


# python3 data_analysis.py "$path_to_output/may15/" "$path_to_output/may15/diff" -e diff -t may15
# python3 data_analysis.py "$path_to_output/may15/" "$path_to_output/may15/merged-all" -e table2diff -t may15

## Destination analysis
# python3 data_analysis.py "$path_to_input" "$path_to_output/may15/" -e destination -t may15
# python3 data_analysis.py "$path_to_input" "$path_to_output/may15/"-e destination-sld -t may15

# python3 data_analysis.py "$path_to_input/results-exp5-ipv4/" "$path_to_output/may15/exp5-ipv4" -e exp5-ipv4 -t may15
# python3 data_analysis.py "$path_to_input/results-exp6-ipv4/" "$path_to_output/may15/exp6-ipv4" -e exp6-ipv4 -t may15
# python3 data_analysis.py "$path_to_input" "$path_to_output/may15/" -e merged-dualv4 -t may15

## Manufacturer analysis
# python3 data_analysis.py "$path_to_input/results-exp2" "$path_to_output/may15/exp2" -e exp2 -t manufacturer-aug26
# python3 data_analysis.py "$path_to_input/results-exp3" "$path_to_output/may15/exp3" -e exp3 -t manufacturer-aug26
# python3 data_analysis.py "$path_to_input/results-exp4" "$path_to_output/may15/exp4" -e exp4 -t manufacturer-aug26
# python3 data_analysis.py "$path_to_input" "$path_to_output/may15/" -e merged -t manufacturer-aug26

# python3 data_analysis.py "$path_to_input/results-exp5-ipv6dns/" "$path_to_output/may15/exp5-ipv6dns" -e exp5-ipv6dns -t manufacturer-aug26
# python3 data_analysis.py "$path_to_input/results-exp6-ipv6dns/" "$path_to_output/may15/exp6-ipv6dns" -e exp6-ipv6dns -t manufacturer-aug26
# python3 data_analysis.py "$path_to_input" "$path_to_output/may15/" -e merged-hybrid -t manufacturer-aug26
# python3 data_analysis.py "$path_to_input" "$path_to_output/may15/" -e merged-all -t manufacturer-aug26


echo "Data analysis completed"