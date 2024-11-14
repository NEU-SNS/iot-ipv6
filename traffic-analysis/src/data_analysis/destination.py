from src.data_analysis.utils import *
from src.data_analysis.get_dict import get_device_category_dict, get_data_dict
from src.data_analysis.df_process import convert_to_per_category, add_total_row, df_to_csv
from src.data_analysis.destination_analysis import destination_analysis_comparison

def destination_analysis(in_dir:str, out_dir:str, experiment_name:str, data_analysis_name:str, device_list:list, csv_name:str='sec5_3', exp_list:list=['exp2', 'exp3', 'exp4'])-> None:
    """
    Perform destination analysis for given experiments and devices.
    
    Parameters:
    - in_dir: Input directory containing data files.
    - out_dir: Output directory to save analysis results.
    - experiment_name: Name of the experiment.
    - data_analysis_name: Name of the data analysis.
    - device_list: List of devices to analyze.
    - csv_name: Name of the CSV file to save results (default: 'sec5_3').
    - exp_list: List of experiments to include in the analysis (default: ['exp2', 'exp3', 'exp4']).
    """
    
    logger.info("Running destination_analysis")
    start_time = time.time()
    # cdn_keywords = ['akamai', 'cloudflare', 'amazonaws' , 'cloudfront', 'devices.a2z.com', '1e100.net', 'node.netflix.net', 'nflxso.net', 'nflxvideo.net']
    
    # output dir
    out_dir_tmp = os.path.join(out_dir, experiment_name)
    if not os.path.exists(out_dir_tmp):
        os.system(f'mkdir -pv {out_dir_tmp}')
    
    # device category
    device_category = get_device_category_dict('ipv6-device-category.csv')
    
    # * initialize dictionaries
    columns = ['Device', 'Category', 'Global Destination', 'Local Destination', 'EUI-64 Destination']
    # df = pd.DataFrame(columns=columns)
    # df['Device'] = device_list
    # df['Category'] = [device_category[device] for device in device_list]
    global_destination_dict = {}    # key: device, value: set of global destinations
    local_destination_dict = {}     # key: device, value: set of local destinations
    global_eui64_destination_dict = {}      # key: device, value: set of global EUI-64 destinations
    ipv4_destination_dict = {}      # key: device, value: set of global IPv4 destinations
    ipv6_aaaa_record = {}       # key: device, value: set of IPv6 AAAA record
    
    global_destination_dict_exp1 = {}
    local_destination_dict_exp1 = {}
    global_eui64_destination_dict_exp1 = {}
    
    global_destination_dict_exp234 = {}
    local_destination_dict_exp234 = {}
    global_eui64_destination_dict_exp234 = {}
    
    global_destination_dict_exp56 = {}
    local_destination_dict_exp56 = {}
    global_eui64_destination_dict_exp56 = {}
    ipv4_destination_dict_exp56 = {}
    all_global_destination_dict_exp56 = {}
    
    
    # * per experiment result processing
    for exp in exp_list:
        logger.info(f"Running destination_analysis for {exp}")
        
        df_tmp = pd.DataFrame(columns=columns)
        df_tmp['Device'] = device_list
        df_tmp['Category'] = [device_category[device] for device in device_list]
        
        destination_name_dict, global_eui64_destination, dns_dict, destination_name_per_version = process_experiment(in_dir, out_dir, exp, device_list, device_category, data_analysis_name, columns)
        
        # dns aaaa record
        update_dns_aaaa_records(device_list, ipv6_aaaa_record, dns_dict)
        
        # update: dig if ip
        update_global_destination_dicts(device_list, destination_name_dict, global_eui64_destination, destination_name_per_version)
        
        # * Only get second-level domain
        if 'sld' in experiment_name:
            convert_to_sld(ipv6_aaaa_record, destination_name_dict, global_eui64_destination, destination_name_per_version)
        
        # save destination name per version to json
        save_destination_name_per_version(out_dir, data_analysis_name, exp, destination_name_per_version)
        
        
        df_tmp['Global Destination'] = [len(destination_name_dict['Global'][device]) for device in device_list]
        df_tmp['Local Destination'] = [len(destination_name_dict['Local'][device]) for device in device_list]
        df_tmp['EUI-64 Destination'] = [len(global_eui64_destination[device]) for device in device_list]
        
        
        for device in device_list:   
            # all global and local and eui-64 destinations 
            global_destination_dict.setdefault(device, set()).update(destination_name_dict['Global'][device])
            local_destination_dict.setdefault(device, set()).update(destination_name_dict['Local'][device])
            global_eui64_destination_dict.setdefault(device, set()).update(global_eui64_destination[device])
            
            # for each experiment
            if exp in ['exp2', 'exp3', 'exp4']:
                global_destination_dict_exp234.setdefault(device, set()).update(destination_name_dict['Global'][device])
                local_destination_dict_exp234.setdefault(device, set()).update(destination_name_dict['Local'][device])
                global_eui64_destination_dict_exp234.setdefault(device, set()).update(global_eui64_destination[device])
            elif exp in ['exp5-ipv6dns', 'exp6-ipv6dns']:
                global_destination_dict_exp56.setdefault(device, set()).update(destination_name_dict['Global'][device])
                local_destination_dict_exp56.setdefault(device, set()).update(destination_name_dict['Local'][device])
                global_eui64_destination_dict_exp56.setdefault(device, set()).update(global_eui64_destination[device])
            elif exp in ['exp5-ipv4', 'exp6-ipv4']: # both ipv6 and ipv4 
                global_destination_dict_exp56.setdefault(device, set()).update(destination_name_per_version['IPv6'][device])
                local_destination_dict_exp56.setdefault(device, set())
                global_eui64_destination_dict_exp56.setdefault(device, set()).update(global_eui64_destination[device])
                ipv4_destination_dict_exp56.setdefault(device, set()).update(destination_name_per_version['IPv4'][device])
                all_global_destination_dict_exp56.setdefault(device, set()).update(destination_name_dict['Global'][device])

            elif exp in ['exp1']:
                global_destination_dict_exp1.setdefault(device, set()).update(destination_name_dict['Global'][device])
                local_destination_dict_exp1.setdefault(device, set()).update(destination_name_dict['Local'][device])
                global_eui64_destination_dict_exp1.setdefault(device, set()).update(global_eui64_destination[device])
                ipv4_destination_dict.setdefault(device, set()).update(destination_name_dict['Global'][device])
                
        save_destination_analysis_results_per_exp(out_dir, data_analysis_name, device_list, out_dir_tmp, columns, exp, df_tmp, destination_name_dict, global_eui64_destination)
    
    return destination_analysis_comparison(
        start_time,
        out_dir_tmp,
        columns,
        experiment_name,
        data_analysis_name,
        device_list,
        [
            global_destination_dict,
            local_destination_dict,
            global_eui64_destination_dict,
            ipv4_destination_dict,
            ipv6_aaaa_record
        ],
        [
            global_destination_dict_exp1,
            local_destination_dict_exp1,
            global_eui64_destination_dict_exp1
        ],
        [
            global_destination_dict_exp234,
            local_destination_dict_exp234,
            global_eui64_destination_dict_exp234
        ],
        [
            global_destination_dict_exp56,
            local_destination_dict_exp56,
            global_eui64_destination_dict_exp56,
            ipv4_destination_dict_exp56,
            all_global_destination_dict_exp56
        ]
    )

def save_destination_analysis_results_per_exp(out_dir, data_analysis_name, device_list, out_dir_tmp, columns, exp, df_tmp, destination_name_dict, global_eui64_destination):
    df_to_csv(df_tmp, out_dir_tmp, exp, data_analysis_name, 'destination_analysis')

    df_tmp_per_category = convert_to_per_category(df_tmp, columns, category_index=2)
    df_tmp_per_category = add_total_row(df_tmp_per_category, index=1)
    df_to_csv(df_tmp_per_category, out_dir_tmp, exp, data_analysis_name, 'destination_analysis_per_category')
        
    for device in device_list:
        destination_name_dict['Global'][device] = list(destination_name_dict['Global'][device])
        destination_name_dict['Local'][device] = list(destination_name_dict['Local'][device])
        global_eui64_destination[device] = list(global_eui64_destination[device])
            
    if not os.path.exists(f'{out_dir}/{exp}'):
        os.system(f'mkdir -pv {out_dir}/{exp}')

    save_json(destination_name_dict, f'{out_dir}/{exp}/{exp}_{data_analysis_name}_destination_name_dict.json')
    save_json(global_eui64_destination, f'{out_dir}/{exp}/{exp}_{data_analysis_name}_global_eui64_destination.json')
        
    destination_name_dict = None
    global_eui64_destination = None

def save_destination_name_per_version(out_dir, data_analysis_name, exp, destination_name_per_version):
    if destination_name_per_version:
        destination_name_per_version_out = {}
            # destination_name_per_version_out['IPv6'] = list(destination_name_per_version['IPv6'])
        destination_name_per_version_out['IPv6'] = {device:list(domain_set) for device, domain_set in destination_name_per_version['IPv6'].items()}
            # destination_name_per_version_out['IPv4'] = list(destination_name_per_version['IPv4'])
        destination_name_per_version_out['IPv4'] = {device:list(domain_set) for device, domain_set in destination_name_per_version['IPv4'].items()}
            
        save_json(destination_name_per_version_out, f'{out_dir}/{exp}/{exp}_{data_analysis_name}_destination_name_per_version.json')

def convert_to_sld(ipv6_aaaa_record, destination_name_dict, global_eui64_destination, destination_name_per_version):
    destination_name_dict['Global'] = get_sld_from_dict(destination_name_dict['Global'])
    global_eui64_destination = get_sld_from_dict(global_eui64_destination)
    if destination_name_per_version:
        destination_name_per_version['IPv6'] = get_sld_from_dict(destination_name_per_version['IPv6'])
        destination_name_per_version['IPv4'] = get_sld_from_dict(destination_name_per_version['IPv4'])
            
    ipv6_aaaa_record = get_sld_from_dict(ipv6_aaaa_record)

def update_global_destination_dicts(device_list, destination_name_dict, global_eui64_destination, destination_name_per_version):
    destination_name_dict['Global'] = update_global_destinations(destination_name_dict['Global']) 
    for device in list(destination_name_dict['Local']):
        for dest in list(destination_name_dict['Local'][device]):
            if dest not in device_list:
                destination_name_dict['Local'][device].remove(dest)
    if destination_name_per_version:
        destination_name_per_version['IPv6'] = update_global_destinations(destination_name_per_version['IPv6'])
        destination_name_per_version['IPv4'] = update_global_destinations(destination_name_per_version['IPv4'])
    global_eui64_destination = update_global_destinations(global_eui64_destination)


def update_dns_aaaa_records(device_list, ipv6_aaaa_record, dns_dict):
    for device in device_list:
        if len(dns_dict) != 0:  # for now, only for dual-stack experiments
            ipv6_aaaa_record.setdefault(device, set()).update(dns_dict[device]['AAAA Res'])
            for res in list(ipv6_aaaa_record[device]):
                if res.endswith('.'):
                    ipv6_aaaa_record[device] = {res.rstrip('.') for res in ipv6_aaaa_record[device]}
        else:
            ipv6_aaaa_record.setdefault(device, set())
            

def process_experiment(in_dir: str, out_dir: str, exp: str, device_list: list[str], data_analysis_name: str) -> tuple:
        
    if exp == 'exp1':
            # destination name dict: extracted IPv4 contacted destination in exp 1
        destination_name_dict = pickle.load(open('%s/dest-analysis/output/exp1_destination_name_dict.pkl' % destination_analysis_path, 'rb'))
        global_eui64_destination = {}
        for device in device_list:
            if device not in destination_name_dict['Global']:
                destination_name_dict['Global'][device] = set()
            if device not in destination_name_dict['Local']:
                destination_name_dict['Local'][device] = set()
            global_eui64_destination[device] = set()
            
            
        dns_dict = {}
        destination_name_per_version = None
            
    else:
            # IPv6 experiments: 
        in_dir_tmp = os.path.join(in_dir, f'results-{exp}')
        get_data_result_list = get_data_dict(in_dir_tmp, exp, device_list)
        global_eui64_destination = get_data_result_list[1]  # global EUI-64 destination
        destination_name_dict = get_data_result_list[2] # all destination IPv6 and IPv4
        if exp in ['exp5-ipv4', 'exp6-ipv4']:
                # dual-stack experiments with IPv4 traffic processed
            destination_name_per_version = get_data_result_list[3]  # IPv6 and IPv4 destination
            dns_file = os.path.join(out_dir, f'{exp}', f'{exp}_{data_analysis_name}_dns_dict.pkl')
            dns_dict = pickle.load(open(dns_file, 'rb'))    # DNS analysis result table
        else:
            destination_name_per_version = None
            dns_dict = {}
    return destination_name_dict,global_eui64_destination,dns_dict,destination_name_per_version

def get_sld_from_dict(input_dict):
    for device in input_dict.keys():
        for dest in list(input_dict[device]):
            if address.validate_ip_address(dest):
                input_dict[device].remove(dest)
                continue
            tmp_dst = dest
            if dest.endswith('.'):
                tmp_dst = dest[:-1]
            if dest.count('.') > 1:
                tmp_dst = '.'.join(tmp_dst.split('.')[-2:])
                input_dict[device].add(tmp_dst)
                input_dict[device].remove(dest)
    return input_dict

def update_global_destinations(input_dict):
    for device in list(input_dict):
        for dest in list(input_dict[device]):
            if address.validate_ip_address(dest):
                dig = dig_x(dest)
                if dig is None or dig == '':
                    continue
                else:
                    input_dict[device].remove(dest)
                    if dig[-1] == '.':
                        dig = dig[:-1]
                        # for cdn in cdn_keywords:
                        #     if cdn in dig:
                        #         dig = '.'.join(dig.split('.')[1:])
                    input_dict[device].add(dig.lower())
    return input_dict

