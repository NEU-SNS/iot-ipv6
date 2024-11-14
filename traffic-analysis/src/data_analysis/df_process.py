from src.data_analysis.utils import *
from src.data_analysis.get_dict import *
def transpose_df(df, index_column_name=['Category', 'Count']):
    df.set_index(index_column_name, inplace=True)
    df = df.T
    # df.reset_index(inplace=True)
    df = df.reset_index().rename(columns={'index': 'Category', '': 'Count'})
    return df
    
def merge_dfs_binary(*args):
    df_merged = args[0].copy()[:-1]
    for df in args[1:]:
        df = df[:-1]
        df_merged = df_merged.set_index(['Device', 'Category']).add(df.set_index(['Device', 'Category']), fill_value=0)
    return convert_to_binary(df_merged.reset_index(), args[0].columns, 2)

def merge_dfs(*args):
    df_merged = args[0].copy()
    for df in args[1:]:
        df_merged = df_merged.set_index(['Device', 'Category']).add(df.set_index(['Device', 'Category']), fill_value=0).reset_index()
        columns_to_check = ['Funtionability IPv6-only', 'IPv6 DNS', 'EUI-64 DNS Req', 'NDP Traffic No Addr', 'Stateful DHCPv6', 'Stateless DHCPv6', 'Data']
        for column in columns_to_check:
            if column in df_merged.columns:
                df_merged[column] = (df_merged[column] > 0).astype(int)
        
    return df_merged

def convert_to_per_category(df, columns, category_index=2):
    df_per_category = df.copy().iloc[:,1:] # remove device column
    # group rows and remove duplicates
    for column in columns[category_index:]:
        df_per_category[column] = df_per_category.groupby('Category')[column].transform('sum')
    df_per_category['Count'] = df_per_category.groupby('Category')['Category'].transform('size')
    # Move 'Count' column to the second position
    cols = df_per_category.columns.tolist()
    cols.insert(1, cols.pop(cols.index('Count')))
    df_per_category = df_per_category[cols]
    
    df_per_category = df_per_category.drop_duplicates(subset=['Category', 'Count'])
    return df_per_category

def add_total_row(df, index=2):
    df_total = df.copy()
    df_total.loc['Total'] = df_total.sum(numeric_only=True, axis=0) # .round().astype(int)
    for i in range(index):
        df_total.iloc[-1, i] = 'Total'
    df_total = df_total.fillna(0) 
    for column in df.columns[index:]:
        df_total[column] = df_total[column].astype(int)
    return df_total
    
def convert_to_binary(df, columns, index):
    df_binary = df.copy()
    for column in columns[index:]:
        df_binary[column] = (df[column] > 0).astype(int)
    # add a total row to the dataframe
    df_binary = add_total_row(df_binary, index)
    
    return df_binary

def df_to_csv(df, out_dir, experiment_name, data_analysis_name, csv_name):
    out_file = os.path.join(out_dir, f'{experiment_name}_{data_analysis_name}_{csv_name}.csv')
    df.to_csv(out_file, index=False)

def add_percentage(df):
    df_percentage = df.copy()
    # df_percentage.reset_index(inplace=False)
    total_num = 93
    df_percentage['Percentage'] = round((100* df_percentage['Total'].astype(int) / total_num),1).astype(str) + '\%'
    return df_percentage


def dns_analysis_table(dns_dict, device_list, get_manufacturer=0):
    logger.info("Running dns_analysis")
    start_time = time.time()
    # dns_analysis_results = {}
    dns_keys = list(dns_dict.get(list(dns_dict.keys())[0]).keys())
    # keys = ['Device', 'Category', 'IPv6 DNS', 'AAAA Req', 'A only Req in IPv6', 'AAAA Req only in IPv4', \
    #         'HTTPS Req', 'SVCB Req',\
    #         'AAAA Res', 'AAAA Res Errorcode', 'SRV Res', 'AAAA SOA Res', 'SOA Res', 'A Res',\
    #             'AAAA Req No AAAA Res', 'AAAA req Got A Res only', 'only AAAA Req But Got A Res',\
    #             'HTTPS Res', 'SVCB Res']
    keys = ['Device', 'Category'] + dns_keys
    df = pd.DataFrame(columns=keys)
    df['Device'] = device_list
    device_category = get_device_category_dict('ipv6-device-category.csv')
    df['Category'] = [device_category[device] for device in device_list]
    if get_manufacturer == 1:
        device_manufacturer = get_device_category_dict('ipv6-device-category.csv', get_manufacturer)
        df['Category'] = [device_manufacturer[device] for device in device_list]
    elif get_manufacturer == 2:
        device_platform = get_device_category_dict('ipv6-device-category.csv', get_manufacturer)
        df['Category'] = [device_platform[device] for device in device_list]
    elif get_manufacturer == 3:
        device_os = get_device_category_dict('ipv6-device-category.csv', get_manufacturer)
        df['Category'] = [device_os[device] for device in device_list]
    for key in keys:
        if key == 'Device' or key == 'Category':
            continue
        elif key in ['IPv6 DNS', 'EUI-64 DNS Req']:
            df[key] = [dns_dict[device][key] for device in device_list]
        else:
            df[key] = [len(dns_dict[device][key]) for device in device_list]
            # if 'DNS' in key:
            #     df = df.rename(columns={key: key.replace('DNS ', '')})

    # df = df.rename(columns={'NDP Traffic No Addr': 'IPv6 NDP Traffic'})
    
    # dns_df = pd.DataFrame(dns_dict).T
    # # Reset the index to make 'Device' a column
    # dns_df.reset_index(inplace=True)
    # dns_df.rename(columns={'index': 'Device'}, inplace=True)
    
    logger.info(f"dns_analysis took {time.time() - start_time} seconds")
    return df



def merge_df_sets(input_dir, experiment_name,  device_list, exp_list):
    device_ipv6_address_type_merged = {device: {} for device in device_list}
    dns_dict_merged = {device: {} for device in device_list}
    for exp in exp_list:
        input_dir_tmp = os.path.join(input_dir, f"results-{exp}")
        
        device_ipv6_address_type = get_device_ipv6_address_dict(f'{input_dir_tmp}/device_ip_{exp}.json', device_list)
        for device in device_list:
            if 'NDP Traffic No Addr' not in device_ipv6_address_type_merged[device]:
                device_ipv6_address_type_merged[device]['NDP Traffic No Addr'] = 0
            device_ipv6_address_type_merged[device]['NDP Traffic No Addr'] += int(device_ipv6_address_type[device]['NDP Traffic No Addr'])
            for key in device_ipv6_address_type[device]:
                if key in ['gua', 'ula', 'lla', 'NDP Traffic No Addr']:
                    continue
                device_ipv6_address_type[device][key] = set(device_ipv6_address_type[device][key])
                device_ipv6_address_type_merged[device].setdefault(key, set()).update(device_ipv6_address_type[device][key])
            
            for key in ['gua', 'ula', 'lla']:
                upper_key = key.upper()
                device_ipv6_address_type_merged[device].setdefault(upper_key, set()).update(device_ipv6_address_type[device][key])
                device_ipv6_address_type_merged[device].setdefault('IPv6 Address', set()).update(device_ipv6_address_type[device][key])
                
            for key in ['Unused GUA', 'Unused ULA', 'Unused LLA']:
                device_ipv6_address_type_merged[device].setdefault('Unused IPv6 Address', set()).update(device_ipv6_address_type[device][key])
            
                
        dns_dict = get_dns_dict(input_dir_tmp, device_list)
        for device in device_list:
            for key in dns_dict[device]:
                if not isinstance(dns_dict[device][key], set):
                    continue
                dns_dict[device][key] = set(dns_dict[device][key])
                dns_dict_merged[device].setdefault(key, set()).update(dns_dict[device][key])
    
    for device in device_list:
        if device_ipv6_address_type_merged[device]['NDP Traffic No Addr'] != 0:
            if (len(device_ipv6_address_type_merged[device]['GUA']) + len(device_ipv6_address_type_merged[device]['ULA']) + len(device_ipv6_address_type_merged[device]['LLA'])) != 0:
                device_ipv6_address_type_merged[device]['NDP Traffic No Addr'] = set()
            else:
                device_ipv6_address_type_merged[device]['NDP Traffic No Addr'] = set([1])
        else:
            device_ipv6_address_type_merged[device]['NDP Traffic No Addr'] = set()
            
    
    # for device in device_list:

    #     a_dns_req = dns_dict_merged[device]['A only Req in IPv6']
    #     # only sent A DNS req without AAAA req in IPv6
    #     dns_dict_merged[device]['A only Req in IPv6'] = a_dns_req.difference(dns_dict_merged[device]['AAAA Req'])
    #     # only sent AAAA DNS Req only in IPv4 but not in IPv6  - hybrid experiments
    #     dns_dict_merged[device]['AAAA Req only in IPv4'] = dns_dict_merged[device]['AAAA Req only in IPv4'].difference(dns_dict_merged[device]['AAAA Req'])
        
        
    #     # AAAA req, received only A DNS res without AAAA res
    #     a_dns_res = set(dns_dict_merged[device].get('A Res', []))
    #     aaaa_dns_req = set(dns_dict_merged[device].get('AAAA Req', []))
    #     aaaa_dns_res = set(dns_dict_merged[device].get('AAAA Res', []))
    #     dns_dict_merged[device]['AAAA req Got A Res only'] = a_dns_res & (aaaa_dns_req - aaaa_dns_res)
        
    #     # Send AAAA Req but without AAAA Res
    #     dns_dict_merged[device]['AAAA Req No AAAA Res'] = aaaa_dns_req - aaaa_dns_res
    #     if len(dns_dict_merged[device]['AAAA Req No AAAA Res']) != len(aaaa_dns_req) - len(aaaa_dns_res):
    #         print(device, len(dns_dict_merged[device]['AAAA Req No AAAA Res']), len(aaaa_dns_req), len(aaaa_dns_res), len(set(dns_dict_merged[device]['AAAA Req No AAAA Res'])))
    #         for i in aaaa_dns_res:
    #             if i not in aaaa_dns_req:
    #                 print(device, i)

    #     # Only sent AAAA req, not A, but got A res instead of AAAA 
    #     dns_dict_merged[device]['only AAAA Req But Got A Res'] = (a_dns_res - a_dns_req) & (aaaa_dns_req - aaaa_dns_res)
    # print(device_ipv6_address_type_merged, dns_dict_merged)
    return device_ipv6_address_type_merged, dns_dict_merged


def generate_analysis_merged_tables(experiment_name, out_dir, data_analysis_name, device_ipv6_address_type_merged, dns_dict_merged, csv_name='sec5_1', exp_list=['exp2', 'exp3', 'exp4']):
    dfs = []
    for exp in exp_list:
        out_dir_tmp = os.path.join(out_dir, exp)
        dfs.append(pd.read_csv(f'{out_dir_tmp}/{exp}_{data_analysis_name}_{csv_name}.csv'))
    
    addr_merged_keys = list(device_ipv6_address_type_merged[list(device_ipv6_address_type_merged.keys())[0]].keys())
    dns_merged_keys = list(dns_dict_merged[list(dns_dict_merged.keys())[0]].keys())
    
    df_merged = merge_dfs(*dfs)
    
    for col in df_merged.columns:
        if col in addr_merged_keys:
            df_merged[col] = [len(device_ipv6_address_type_merged[device][col]) for device in df_merged['Device']]
        if col in dns_merged_keys:
            # print('col:', col)
            df_merged[col] = [len(dns_dict_merged[device][col]) for device in df_merged['Device']]
            
    df_merged_binary = convert_to_binary(df_merged, df_merged.columns, 2)
    
    out_dir = os.path.join(out_dir, experiment_name)
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
    df_to_csv(df_merged, out_dir, experiment_name, data_analysis_name, csv_name)
    df_to_csv(df_merged_binary, out_dir, experiment_name, data_analysis_name, f'{csv_name}_binary')
    
    df_per_category = convert_to_per_category(df_merged, df_merged.columns, category_index=2)
    df_per_category_with_total = add_total_row(df_per_category, index=1)
    df_per_category_binary = convert_to_per_category(df_merged_binary.iloc[:-1], df_merged_binary.columns, category_index=2)
    df_per_category_binary = add_total_row(df_per_category_binary, index=1)

    if 'manufacturer' in data_analysis_name:
        df_per_category = df_per_category[df_per_category['Count'] >= 3]
        df_per_category_with_total = df_per_category_with_total[df_per_category_with_total['Count'] >= 3]
        df_per_category_binary = df_per_category_binary[df_per_category_binary['Count'] >= 3]
    df_to_csv(df_per_category, out_dir, experiment_name, data_analysis_name, f'{csv_name}_per_category')
    df_to_csv(df_per_category_with_total, out_dir, experiment_name, data_analysis_name, f'{csv_name}_per_category_with_total')
    df_to_csv(df_per_category_binary, out_dir, experiment_name, data_analysis_name, f'{csv_name}_per_category_binary')
    
    # transpose the dataframes
    df_per_category_T = transpose_df(df_per_category, index_column_name=['Category', 'Count'])
    df_per_category_with_total_T = transpose_df(df_per_category_with_total, index_column_name=['Category', 'Count'])
    df_per_category_binary_T = transpose_df(df_per_category_binary, index_column_name=['Category', 'Count'])
    df_per_category_binary_T = add_percentage(df_per_category_binary_T)
    df_to_csv(df_per_category_T, out_dir, experiment_name, data_analysis_name, f'{csv_name}_per_category_T')
    df_to_csv(df_per_category_with_total_T, out_dir, experiment_name, data_analysis_name, f'{csv_name}_per_category_with_total_T')
    df_to_csv(df_per_category_binary_T, out_dir, experiment_name, data_analysis_name, f'{csv_name}_per_category_binary_T')
    return df_merged, df_merged_binary, df_per_category, df_per_category_binary
    
