#!~/.venvs/ipv6/bin/python3
from src.data_analysis.utils import *
from src.data_analysis.get_dict import get_device_year_dict, get_device_category_dict, get_device_functionality_dict, get_device_ipv6_address_dict, get_dns_dict, get_dhcpv6_req_dict, get_data_dict
from src.data_analysis.df_process import convert_to_binary, convert_to_per_category, add_total_row, df_to_csv, merge_dfs, transpose_df, add_percentage, dns_analysis_table, generate_analysis_merged_tables, merge_df_sets
from src.data_analysis.destination import destination_analysis
from src.helper.logger import setup_logger

mac_dict = {}
inv_mac_dict = {}
logger = None 


def sec5_1(input_dir, out_dir, experiment_name, data_analysis_name, device_list, get_manufacturer=0, get_year=0):
    
    columns = ['Device', 'Category', 'Funtionability IPv6-only', 'NDP Traffic No Addr',\
            'IPv6 Address', 'GUA', 'ULA', 'LLA',  'GUA EUI-64 Address', 'Local EUI-64 Address', 'Stateful DHCPv6', \
                'Unused IPv6 Address', 'Unused GUA', 'Unused ULA', 'Unused LLA', 'Unused GUA EUI-64',  \
            'IPv6 DNS', 'AAAA Req', 'AAAA Res', 'Stateless DHCPv6', \
            'Global Data Comm', 'Local Data Comm', 'Data', 'Global Data Comm EUI-64', \
                'Global Data Comm Volume','Global Data Comm IPv6 Volume', 'Global Data Comm IPv4 Volume' ]   # , 'Global Data Comm IPv6 Fraction'
    
    # create a pandas dataframe
    df = pd.DataFrame(columns=columns)
    df['Device'] = device_list
    device_category = get_device_category_dict('ipv6-device-category.csv')
    df['Category'] = [device_category[device] for device in device_list]
    if get_manufacturer == 1:
        device_manufacturer = get_device_category_dict('ipv6-device-category.csv', get_manufacturer)
        df['Category'] = [device_manufacturer[device] for device in device_list]
    elif get_year == 1:
        device_year = get_device_year_dict('device_year.json')
        df['Category'] = [device_year[device] for device in device_list]
    elif get_manufacturer == 2:
        device_platform = get_device_category_dict('ipv6-device-category.csv', get_manufacturer)
        df['Category'] = [device_platform[device] for device in device_list]
    elif get_manufacturer == 3:
        device_os = get_device_category_dict('ipv6-device-category.csv', get_manufacturer)
        df['Category'] = [device_os[device] for device in device_list]
    
    device_functionality = get_device_functionality_dict(device_list)
    df['Funtionability IPv6-only'] = [device_functionality[device] for device in device_list]   
    # Address
    device_ipv6_address_type = get_device_ipv6_address_dict(f'{input_dir}/device_ip_{experiment_name}.json', device_list)
    df['IPv6 Address'] = [len(device_ipv6_address_type[device]['gua']) + len(device_ipv6_address_type[device]['ula']) + len(device_ipv6_address_type[device]['lla']) for device in device_list]
    df['GUA'] = [len(device_ipv6_address_type[device]['gua']) for device in device_list]
    df['ULA'] = [len(device_ipv6_address_type[device]['ula']) for device in device_list]
    df['LLA'] = [len(device_ipv6_address_type[device]['lla']) for device in device_list]
    df['GUA EUI-64 Address'] = [len(device_ipv6_address_type[device]['GUA EUI-64 Address']) for device in device_list]
    df['Local EUI-64 Address'] = [len(device_ipv6_address_type[device]['Local EUI-64 Address']) for device in device_list]
    
    df['Unused IPv6 Address'] = [len(device_ipv6_address_type[device]['Unused GUA']) + len(device_ipv6_address_type[device]['Unused ULA']) + len(device_ipv6_address_type[device]['Unused LLA']) for device in device_list]
    df['Unused GUA'] = [len(device_ipv6_address_type[device]['Unused GUA']) for device in device_list]
    df['Unused ULA'] = [len(device_ipv6_address_type[device]['Unused ULA']) for device in device_list]
    df['Unused LLA'] = [len(device_ipv6_address_type[device]['Unused LLA']) for device in device_list]
    df['Unused GUA EUI-64'] = [len(device_ipv6_address_type[device]['Unused GUA EUI-64']) for device in device_list]
    
    dhcpv6_req_dict = get_dhcpv6_req_dict(input_dir, device_list)
    df['Stateful DHCPv6'] = [dhcpv6_req_dict[device]['Stateful DHCPv6'] for device in device_list]
    df['NDP Traffic No Addr'] = [device_ipv6_address_type[device]['NDP Traffic No Addr'] for device in device_list]
    
    # DNS
    df['Stateless DHCPv6'] = [dhcpv6_req_dict[device]['Stateless DHCPv6'] for device in device_list]
    dns_dict = get_dns_dict(input_dir, device_list)
    df['IPv6 DNS'] = [dns_dict[device]['IPv6 DNS'] for device in device_list]
    df['AAAA Req'] = [len(dns_dict[device]['AAAA Req']) for device in device_list]
    df['AAAA Res'] = [len(dns_dict[device]['AAAA Res']) for device in device_list]
    
    # Data
    data_dict = get_data_dict(input_dir, experiment_name, device_list)[0]
    # global_eui64_destination, destination_name_dict, _ 
    # with open(f'{out_dir}/{experiment_name}_{data_analysis_name}_global_eui64_destination.pkl', 'wb') as f:
    #     pickle.dump(global_eui64_destination, f)
    # with open(f'{out_dir}/{experiment_name}_{data_analysis_name}_destination_name_dict.pkl', 'wb') as f:
    #     pickle.dump(destination_name_dict, f)
    df['Local Data Comm'] = [data_dict[device]['Local Data Comm'] for device in device_list]
    df['Global Data Comm'] = [data_dict[device]['Global Data Comm'] for device in device_list]
    df['Data'] = [data_dict[device]['Data'] for device in device_list]
    df['Global Data Comm EUI-64'] = [data_dict[device]['Global Data Comm EUI-64'] for device in device_list]
    df['Global Data Comm Volume'] = [data_dict[device]['Global Data Comm Volume'] for device in device_list]
    df['Global Data Comm IPv6 Volume'] = [data_dict[device]['Global Data Comm IPv6 Volume'] for device in device_list]
    df['Global Data Comm IPv4 Volume'] = [data_dict[device]['Global Data Comm IPv4 Volume'] for device in device_list]
    # df['Global Data Comm IPv6 Fraction'] = [
    #     round(data_dict[device]['Global Data Comm IPv6 Volume'] / data_dict[device]['Global Data Comm Volume'], 3)
    #     if data_dict[device]['Global Data Comm Volume'] != 0 else 0
    #     for device in device_list
    # ]
    
    for device in device_list:
        if data_dict[device]['Global Data Comm'] != 0 and dns_dict[device]['IPv6 DNS'] == 0:
            logger.debug(f'{device}: Has Global IPv6 Data no IPv6 DNS')
    
    # create a new dataframe with all binary data: if the value is greater than 0, set it to 1
    df_binary = convert_to_binary(df, columns, index=2)
    df_per_category = convert_to_per_category(df, columns, category_index=2)
    df_per_category_with_total = add_total_row(df_per_category, index=1)
    # df_per_category_binary = convert_to_binary(df_per_category, df_per_category.columns, index=1)
    df_per_category_binary = convert_to_per_category(df_binary, df_binary.columns, category_index=2)

    df_to_csv(df, out_dir, experiment_name, data_analysis_name, 'sec5_1')
    df_to_csv(df_binary, out_dir, experiment_name, data_analysis_name, 'sec5_1_binary')
    df_to_csv(df_per_category, out_dir, experiment_name, data_analysis_name, 'sec5_1_per_category')
    df_to_csv(df_per_category_with_total, out_dir, experiment_name, data_analysis_name, 'sec5_1_per_category_with_total')
    df_to_csv(df_per_category_binary, out_dir, experiment_name, data_analysis_name, 'sec5_1_per_category_binary')

    df_dns = dns_analysis_table(dns_dict, device_list, get_manufacturer=get_manufacturer)
    df_to_csv(df_dns, out_dir, experiment_name, data_analysis_name, 'dns_analysis')
    # save DNS_Dict to pickle file
    with open(f'{out_dir}/{experiment_name}_{data_analysis_name}_dns_dict.pkl', 'wb') as f:
        pickle.dump(dns_dict, f)
    return df

def sec_5_1_merge_ipv6_only(in_dir, experiment_name, out_dir, data_analysis_name, device_list, csv_name='sec5_1', exp_list=['exp2', 'exp3', 'exp4']):
    if data_analysis_name.startswith('dad'):
        dfs = []
        for exp in exp_list:
            df_tmp = pd.read_csv(f'{out_dir}/{exp}/{exp}_{data_analysis_name}_dad.csv')
            dfs.append(df_tmp)
            # df_binary_tmp = pd.read_csv(f'{out_dir}/{exp}/{exp}_{data_analysis_name}_dad_binary.csv')
        df_merged = merge_dfs(*dfs)
        df_merged_binary = convert_to_binary(df_merged, df_merged.columns, 2)
        # merge_dfs_binary()
        df_per_category = convert_to_per_category(df_merged, df_merged.columns, category_index=2)
        df_per_category_with_total = add_total_row(df_per_category, index=1)
        df_per_category_binary = convert_to_per_category(df_merged_binary, df_merged_binary.columns, category_index=2)
        out_dir = os.path.join(out_dir, experiment_name)
        df_to_csv(df_merged, out_dir, experiment_name, data_analysis_name, 'dad')
        df_to_csv(df_merged_binary, out_dir, experiment_name, data_analysis_name, 'dad_binary')
        df_to_csv(df_per_category, out_dir, experiment_name, data_analysis_name, 'dad_per_category')
        df_to_csv(df_per_category_with_total, out_dir, experiment_name, data_analysis_name, 'dad_per_category_with_total')
        df_to_csv(df_per_category_binary, out_dir, experiment_name, data_analysis_name, 'dad_per_category_binary')
        return 0
    
    
    device_ipv6_address_type_merged, dns_dict_merged = merge_df_sets(in_dir, experiment_name, device_list, exp_list)
    df_merged, df_merged_binary, df_per_category, df_per_category_binary = generate_analysis_merged_tables(experiment_name, out_dir, data_analysis_name, device_ipv6_address_type_merged, dns_dict_merged, csv_name, exp_list)
    
    table_5_1(df_per_category_binary.reset_index(), os.path.join(out_dir, experiment_name), experiment_name, data_analysis_name)
    table_5_2(df_per_category_binary.reset_index(), os.path.join(out_dir, experiment_name), experiment_name, data_analysis_name)
    generate_analysis_merged_tables(experiment_name, out_dir, data_analysis_name, device_ipv6_address_type_merged, dns_dict_merged, 'dns_analysis', exp_list)
    
    return 0

def table_5_1(df, out_dir, experiment_name, data_analysis_name):
    # Get a list of all columns in the DataFrame
    cols_to_drop = df.columns.tolist()
    # Remove the columns you want to keep from the list
    cols_to_keep = ['Category', 'Count', 'Funtionability IPv6-only', 'NDP Traffic No Addr', 'IPv6 Address', 'IPv6 DNS', 'Global Data Comm']
    for col in cols_to_keep:
        try:
            cols_to_drop.remove(col)
        except:
            print(col, cols_to_drop)
            exit(1)
    # Drop the remaining columns
    # df = df.drop(columns=cols_to_drop)
    df = df[cols_to_keep]
    df.loc[:, 'NDP Traffic No Addr'] = df['NDP Traffic No Addr'] + df['IPv6 Address']
    df = df.rename(columns={'NDP Traffic No Addr': 'IPv6 NDP Traffic'})
    df = df.rename(columns={'Global Data Comm': 'Global TCP/UDP Data'})
    df_to_csv(df, out_dir, experiment_name, data_analysis_name, 'table_5_1')
    return 0

def table_5_2(df, out_dir, experiment_name, data_analysis_name):
    cols_to_drop = df.columns.tolist()
    # Remove the columns you want to keep from the list
    cols_to_keep = ['Category', 'Count', 'Funtionability IPv6-only', 'NDP Traffic No Addr', 'IPv6 Address', 'GUA', 'AAAA Req','AAAA Res', 'Global Data Comm']
    for col in cols_to_keep:
        try:
            cols_to_drop.remove(col)
        except:
            print(col, cols_to_drop)
            exit(1)
    # Drop the remaining columns
    # df = df.drop(columns=cols_to_drop)
    df = df[cols_to_keep]
    
    
    pd.options.mode.chained_assignment = None
    
    df.loc[:, 'IPv6 NDP Traffic'] = df['NDP Traffic No Addr'] + df['IPv6 Address']
    df.loc[:, 'No IPv6'] = df['Count'] - df['IPv6 NDP Traffic']
    df.loc[:, 'IPv6 Address but No DNS'] = df['IPv6 Address'] - df['AAAA Req']
    df.loc[:, 'IPv6 DNS but No Data'] = df['AAAA Req'] - df['Global Data Comm']
    df.loc[:, 'IPv6 Data but Not Func'] = df['Global Data Comm'] - df['Funtionability IPv6-only']
    df = df.rename(columns={'AAAA Req': 'AAAA DNS Req'})
    df = df.rename(columns={'Global Data Comm': 'Global TCP/UDP Data'})
    reorder_cols = ['Category', 'Count', 'No IPv6', 'IPv6 NDP Traffic', 'NDP Traffic No Addr', 'IPv6 Address', 'GUA', 'IPv6 Address but No DNS', 'AAAA DNS Req','AAAA Res','IPv6 DNS but No Data', 'Global TCP/UDP Data', 'IPv6 Data but Not Func', 'Funtionability IPv6-only']
    df = df[reorder_cols]
    
    
    df_to_csv(df, out_dir, experiment_name, data_analysis_name, 'table_5_2')
    df_t = transpose_df(df)
    df_t = add_percentage(df_t)
    df_to_csv(df_t, out_dir, experiment_name, data_analysis_name, 'table_5_2_T')
    
    return 0

def table_2_diff(in_dir, experiment_name, out_dir, data_analysis_name, csv_name='table_5_2', exp_list=['merged', 'merged-hybrid']):
    dfs_binary = []
    for exp in exp_list:
        out_dir_tmp = os.path.join(in_dir, exp)
        dfs_binary.append(pd.read_csv(f'{out_dir_tmp}/{exp}_{data_analysis_name}_{csv_name}.csv'))
    df_diff1_binary = dfs_binary[1].copy().set_index(['Category']).subtract(dfs_binary[0].set_index(['Category']), fill_value=0).reset_index()
    df_to_csv(df_diff1_binary, out_dir, experiment_name, data_analysis_name, 'table_2_diff')
    df_diff1_binary_T = transpose_df(df_diff1_binary)
    df_diff1_binary_T = add_percentage(df_diff1_binary_T)
    df_to_csv(df_diff1_binary_T, out_dir, experiment_name, data_analysis_name, 'table_2_diff_T')

def sec5_1_diff(in_dir, experiment_name, out_dir, data_analysis_name, csv_name='sec5_1', exp_list=['exp2', 'exp3', 'exp4']):
    # exp2: RDNSS + Stateless DHCPv6
    # exp3: RDNSS
    # exp4: RDNSS + Stateless DHCPv6 + Stateful DHCPv6
    # diff1: exp2-exp3 - Stateless DHCPv6's impact on DNS and IPv6 support
    # diff2: exp4-exp2 - if they use Stateful DHCPv6
    
    # df_merged, df_merged_binary, df_per_category, df_per_category_binary = generate_analysis_merged_tables(experiment_name, out_dir, data_analysis_name, csv_name, exp_list)
    dfs = []
    for exp in exp_list:
        out_dir_tmp = os.path.join(in_dir, exp)
        dfs.append(pd.read_csv(f'{out_dir_tmp}/{exp}_{data_analysis_name}_{csv_name}.csv'))
    
    dfs_binary = []
    for exp in exp_list:
        out_dir_tmp = os.path.join(in_dir, exp)
        dfs_binary.append(pd.read_csv(f'{out_dir_tmp}/{exp}_{data_analysis_name}_{csv_name}_binary.csv'))
    
    df_diff1 = dfs[0].copy().set_index(['Device', 'Category']).subtract(dfs[1].set_index(['Device', 'Category']), fill_value=0).reset_index()
    df_diff1_binary = dfs_binary[0].copy().set_index(['Device', 'Category']).subtract(dfs_binary[1].set_index(['Device', 'Category']), fill_value=0).reset_index()
    
    df_diff2 = dfs[2].copy().set_index(['Device', 'Category']).subtract(dfs[0].set_index(['Device', 'Category']), fill_value=0).reset_index()
    df_diff2_binary = dfs_binary[2].copy().set_index(['Device', 'Category']).subtract(dfs_binary[0].set_index(['Device', 'Category']), fill_value=0).reset_index()
    
    df_to_csv(df_diff1, out_dir, experiment_name, data_analysis_name, 'diff1')
    df_to_csv(df_diff1_binary, out_dir, experiment_name, data_analysis_name, 'diff1_binary')
    df_to_csv(df_diff2, out_dir, experiment_name, data_analysis_name, 'diff2')
    df_to_csv(df_diff2_binary, out_dir, experiment_name, data_analysis_name, 'diff2_binary')
    
    return 0

def check_DAD_merged(in_dir, out_dir, experiment_name, data_analysis_name, device_list, exp_list=['exp2', 'exp3', 'exp4', 'exp5-ipv6dns', 'exp6-ipv6dns']):
    """
        Check if the device has Duplicate Address Detection (DAD)
    """
    logger.info("Running check_DAD_merged")
    start_time = time.time()
    columns = ['Device', 'Category', 'DAD', 'DAD Addr' ,'IPv6 Address', 'No DAD Addr', 'No DAD EUI-64']
    df = pd.DataFrame(columns=columns)
    for col in columns:
        df[col] = [0 for device in device_list]
    df['Device'] = device_list
    device_category = get_device_category_dict('ipv6-device-category.csv')
    df['Category'] = [device_category[device] for device in device_list]
    dad_dict = {}
    
    for device in device_list:
        dad = 0
        dad_dict[device] = set()
        for exp in exp_list:
            
            filepath = os.path.join(in_dir, f'results-{exp}', device, 'ns.csv')
            if not os.path.exists(filepath):
                continue
            with open(filepath, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row['src_ip'] == '::':
                        dad = 1
                        dad_dict[device].add(row['target'])
        df.loc[df['Device'] == device, 'DAD'] = dad
        df.loc[df['Device'] == device, 'DAD Addr'] = len(dad_dict[device])
    ipv6_gua_tmp = {}
    ipv6_ula_tmp = {}
    ipv6_lla_tmp = {}
    eui_64_tmp = {}
    for device in device_list:
        ipv6_gua_tmp[device] = set()
        ipv6_ula_tmp[device] = set()
        ipv6_lla_tmp[device] = set()
        eui_64_tmp[device] = set()
    for exp in exp_list:
        if 'exp2' in exp:
            tmp_exp = 'exp2'
        else:
            tmp_exp = exp
        device_ipv6_address_type = get_device_ipv6_address_dict(f'{in_dir}/results-{exp}/device_ip_{tmp_exp}.json', device_list)
        #  = [len(device_ipv6_address_type[device]['gua']) + len(device_ipv6_address_type[device]['ula']) + len(device_ipv6_address_type[device]['lla']) for device in device_list]
        for device in device_list:
            ipv6_gua_tmp[device].update(set(device_ipv6_address_type[device]['gua']))
            ipv6_ula_tmp[device].update(set(device_ipv6_address_type[device]['ula']))
            ipv6_lla_tmp[device].update(set(device_ipv6_address_type[device]['lla']))
            eui_64_tmp[device].update(set(device_ipv6_address_type[device]['GUA EUI-64 Address']))
            eui_64_tmp[device].update(set(device_ipv6_address_type[device]['Local EUI-64 Address']))
    df['IPv6 Address'] = [len(ipv6_gua_tmp[device]) + len(ipv6_ula_tmp[device]) + len(ipv6_lla_tmp[device]) for device in device_list]
    not_dad = {}
    eui_not_dad = {}
    no_dad_gua = 0
    no_dad_ula = 0
    no_dad_lla = 0
    no_dad_eui64 = 0
    for device in device_list:
        not_dad[device] = set()
        eui_not_dad[device] = set()
        for gua in ipv6_gua_tmp[device]:
            if gua not in dad_dict[device]:
                not_dad[device].add(gua)
                no_dad_gua += 1
        for ula in ipv6_ula_tmp[device]:
            if ula not in dad_dict[device]:
                not_dad[device].add(ula)
                no_dad_ula += 1
        for lla in ipv6_lla_tmp[device]:
            if lla not in dad_dict[device]:
                not_dad[device].add(lla)
                no_dad_lla += 1
        for eui_64 in eui_64_tmp[device]:
            if eui_64 not in dad_dict[device]:
                # not_dad[device].add(eui_64)
                eui_not_dad[device].add(eui_64)
                no_dad_eui64 += 1
        # print(device, not_dad[device])
    logger.info(f'No DAD GUA: {no_dad_gua}, No DAD ULA: {no_dad_ula}, No DAD LLA: {no_dad_lla}, No DAD EUI-64: {no_dad_eui64}')
    df['No DAD Addr'] = [len(not_dad[device]) for device in device_list]
    df['No DAD EUI-64'] = [len(eui_not_dad[device]) for device in device_list]
    
    df_binary = convert_to_binary(df, columns, 2)
    df_binary_per_category = convert_to_per_category(df_binary, columns, category_index=2)
    # df_binary_per_category_with_total = add_total_row(df_binary_per_category, index=1)
    df_per_category = convert_to_per_category(df, columns, category_index=2)
    df_per_category_with_total = add_total_row(df_per_category, index=1)
    # experiment_name = experiment_name + '_no_exp2_'
    df_to_csv(df, out_dir, experiment_name, data_analysis_name, 'dad')
    df_to_csv(df_binary, out_dir, experiment_name, data_analysis_name, 'dad_binary')
    df_to_csv(df_binary_per_category, out_dir, experiment_name, data_analysis_name, 'dad_binary_per_category')
    df_to_csv(df_per_category_with_total, out_dir, experiment_name, data_analysis_name, 'dad_per_category_with_total')

    return 0

def check_DAD(in_dir, out_dir, experiment_name, data_analysis_name, device_list):
    """
        Check if the device has Duplicate Address Detection (DAD)
    """
    logger.info("Running check_DAD")
    start_time = time.time()
    columns = ['Device', 'Category', 'DAD', 'DAD Addr' ,'IPv6 Address', 'No DAD Addr']
    df = pd.DataFrame(columns=columns)
    for col in columns:
        df[col] = [0 for device in device_list]
    df['Device'] = device_list
    device_category = get_device_category_dict('ipv6-device-category.csv')
    df['Category'] = [device_category[device] for device in device_list]
    dad_dict = {}
    for device in device_list:
        dad = 0
        dad_dict[device] = set()
        filepath = os.path.join(in_dir, device, 'ns.csv')
        if not os.path.exists(filepath):
            continue
        with open(filepath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['src_ip'] == '::':
                    dad = 1
                    dad_dict[device].add(row['target'])
        df.loc[df['Device'] == device, 'DAD'] = dad
        df.loc[df['Device'] == device, 'DAD Addr'] = len(dad_dict[device])
    
    device_ipv6_address_type = get_device_ipv6_address_dict(f'{in_dir}/device_ip_{experiment_name}.json', device_list)
    df['IPv6 Address'] = [len(device_ipv6_address_type[device]['gua']) + len(device_ipv6_address_type[device]['ula']) + len(device_ipv6_address_type[device]['lla']) for device in device_list]
    not_dad = {}
    no_dad_gua = 0
    no_dad_ula = 0
    no_dad_lla = 0
    for device in device_list:
        not_dad[device] = set()
        for gua in device_ipv6_address_type[device]['gua']:
            if gua not in dad_dict[device]:
                not_dad[device].add(gua)
                no_dad_gua += 1
        for ula in device_ipv6_address_type[device]['ula']:
            if ula not in dad_dict[device]:
                not_dad[device].add(ula)
                no_dad_ula += 1
        for lla in device_ipv6_address_type[device]['lla']:
            if lla not in dad_dict[device]:
                not_dad[device].add(lla)
                no_dad_lla += 1
        # print(device, not_dad[device])
    logger.info(f'No DAD GUA: {no_dad_gua}, No DAD ULA: {no_dad_ula}, No DAD LLA: {no_dad_lla}')
    df['No DAD Addr'] = [len(not_dad[device]) for device in device_list]
    
    
    df_binary = convert_to_binary(df, columns, 2)
    df_per_category = convert_to_per_category(df, columns, category_index=2)
    df_per_category_with_total = add_total_row(df_per_category, index=1)

    df_to_csv(df, out_dir, experiment_name, data_analysis_name, 'dad')
    df_to_csv(df_binary, out_dir, experiment_name, data_analysis_name, 'dad_binary')
    df_to_csv(df_per_category, out_dir, experiment_name, data_analysis_name, 'dad_per_category')
    df_to_csv(df_per_category_with_total, out_dir, experiment_name, data_analysis_name, 'dad_per_category_with_total')

    return 0


def main():
    in_dir, out_dir, experiment_name, data_analysis_name = arugment_parser()
    global logger
    logger = setup_logger('IoTv6', f'logs/data_analysis_{experiment_name}_{data_analysis_name}.log', logging.DEBUG)
    logger.info(f"Running {sys.argv[0]} -e:{experiment_name}, -t:{data_analysis_name}...")
    logger.info("Input files located in: %s\n Output files placed in: %s\n" % (in_dir, out_dir))
    device_list = init()

    if experiment_name.startswith('diff'):
        sec5_1_diff(in_dir, experiment_name, out_dir, data_analysis_name, csv_name='sec5_1', exp_list=['exp2', 'exp3', 'exp4'])
    elif experiment_name.startswith('merged'):
        if 'hybrid' in experiment_name:
            sec_5_1_merge_ipv6_only(in_dir, experiment_name, out_dir, data_analysis_name, device_list, csv_name='sec5_1', exp_list=['exp5-ipv6dns', 'exp6-ipv6dns'])
        elif 'dualv4' in experiment_name:
            sec_5_1_merge_ipv6_only(in_dir, experiment_name, out_dir, data_analysis_name, device_list, csv_name='sec5_1', exp_list=['exp5-ipv4', 'exp6-ipv4'])
        elif 'all' in experiment_name:
            sec_5_1_merge_ipv6_only(in_dir, experiment_name, out_dir, data_analysis_name, device_list, csv_name='sec5_1', exp_list=['exp2', 'exp3', 'exp4', 'exp5-ipv6dns', 'exp6-ipv6dns'])
        else:
            sec_5_1_merge_ipv6_only(in_dir, experiment_name, out_dir, data_analysis_name, device_list, csv_name='sec5_1', exp_list=['exp2', 'exp3', 'exp4'])

    elif experiment_name.startswith('table2diff'):
        table_2_diff(in_dir, experiment_name, out_dir, data_analysis_name, csv_name='table_5_2', exp_list=['merged', 'merged-hybrid'])
    elif experiment_name.startswith('destination'):
        destination_analysis(in_dir, out_dir, experiment_name, data_analysis_name, device_list, csv_name='sec5_3', exp_list=['exp1', 'exp2', 'exp3', 'exp4','exp5-ipv4', 'exp6-ipv4']) # 'exp5-ipv6dns', 'exp6-ipv6dns'
        
    elif experiment_name.startswith('dadmerged'):
        check_DAD_merged(in_dir, out_dir, experiment_name, data_analysis_name, device_list, exp_list=['exp2-full-icmpv6', 'exp3', 'exp4', 'exp5-ipv6dns', 'exp6-ipv6dns']) # 'exp2', 
    elif data_analysis_name.startswith('manufacturer'):
        sec5_1(in_dir, out_dir, experiment_name, data_analysis_name, device_list, get_manufacturer=1) 
    elif data_analysis_name.startswith('platform'):
        sec5_1(in_dir, out_dir, experiment_name, data_analysis_name, device_list, get_manufacturer=2) 
    elif data_analysis_name.startswith('os'):
        sec5_1(in_dir, out_dir, experiment_name, data_analysis_name, device_list, get_manufacturer=3) 
    elif data_analysis_name.startswith('year'):
        sec5_1(in_dir, out_dir, experiment_name, data_analysis_name, device_list, get_year=1) 
    elif data_analysis_name.startswith('dad'):
        check_DAD(in_dir, out_dir, experiment_name, data_analysis_name, device_list)
    else:
        sec5_1(in_dir, out_dir, experiment_name, data_analysis_name, device_list)
    
if __name__ == "__main__":
    
    main()