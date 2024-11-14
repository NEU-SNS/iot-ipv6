from src.data_analysis.utils import *
from src.data_analysis.get_dict import get_device_category_dict
from src.data_analysis.df_process import convert_to_per_category, add_total_row, df_to_csv, transpose_df


def destination_analysis_comparison(start_time, out_dir_tmp:str, columns:list, experiment_name:str, data_analysis_name:str, device_list:list, dicts:dict[dict,dict,dict,dict,dict], dicts_exp1:dict[dict,dict,dict], dicts_exp234:dict[dict,dict,dict], dicts_exp56:dict[dict,dict,dict,dict,dict])-> None:
    
    def update_dataframe(df, device_list, global_dict, local_dict, eui64_dict):
        df['Global Destination'] = [len(global_dict[device]) for device in device_list]
        df['Local Destination'] = [len(local_dict[device]) for device in device_list]
        df['EUI-64 Destination'] = [len(eui64_dict[device]) for device in device_list]
        
    def calculate_fractions(df, numerator_col, denominator_col, new_col_name):
        df[new_col_name] = (np.where(df[denominator_col] != 0, df[numerator_col] / df[denominator_col], 0) * 100).round(1)
        # Convert to string and add '%'
        df[new_col_name] = df[new_col_name].astype(str) + '%'
        
    # device category
    device_category = get_device_category_dict('ipv6-device-category.csv')
    
    global_destination_dict, local_destination_dict, global_eui64_destination_dict, ipv4_destination_dict, ipv6_aaaa_record = dicts
    
    global_destination_dict_exp1, local_destination_dict_exp1, global_eui64_destination_dict_exp1 = dicts_exp1
    
    global_destination_dict_exp234, local_destination_dict_exp234, global_eui64_destination_dict_exp234 = dicts_exp234
    
    # global_destination_dict_exp56 only contains IPv6 destinations; all_global_destination_dict_exp56 contains both IPv6 and IPv4 destinations
    global_destination_dict_exp56, local_destination_dict_exp56, global_eui64_destination_dict_exp56, ipv4_destination_dict_exp56, all_global_destination_dict_exp56 = dicts_exp56
    
    
    # dataframe initialization
    df = initialize_dataframes(columns, device_list, device_category)
    df_exp1 = initialize_dataframes(columns, device_list, device_category)
    df_exp234 = initialize_dataframes(columns, device_list, device_category)
    df_exp56 = initialize_dataframes(columns, device_list, device_category)
    
    
    # * All Global destinations IPv6 and IPv4
    update_dataframe(df, device_list, global_destination_dict, local_destination_dict, global_eui64_destination_dict)
    
    # * All IPv6 global destination, IPv6 local destination, IPv4 global destination
    ipv6_global_destination_dict = {}
    ipv6_local_destination_dict = {}
    for device in global_destination_dict.keys():
        
        ipv6_global_destination_dict.setdefault(device, set()).update(global_destination_dict_exp234[device])
        ipv6_global_destination_dict.setdefault(device, set()).update(global_destination_dict_exp56[device])
        ipv6_local_destination_dict.setdefault(device, set()).update(local_destination_dict_exp234[device])
        ipv6_local_destination_dict.setdefault(device, set()).update(local_destination_dict_exp56[device])
        
        # IPv4 global destination (Exp1 and Exp56)
        ipv4_destination_dict.setdefault(device, set()).update(ipv4_destination_dict_exp56[device])
        
    
    
    
    # * Per category results CSV
    # categorize_and_save_df_to_csv(
    #     df, columns, category_index=2, out_dir_tmp=out_dir_tmp,
    #     experiment_name=experiment_name, data_analysis_name=data_analysis_name,
    #     file_suffix='destination_analysis', per_category_suffix='destination_analysis_per_category'
    # )
    
    # # * Save Per Experiment results
    # update_dataframe(df_exp1, device_list, global_destination_dict_exp1, local_destination_dict_exp1, global_eui64_destination_dict_exp1)
    # categorize_and_save_df_to_csv(
    #     df_exp1, columns, category_index=2, out_dir_tmp=out_dir_tmp,
    #     experiment_name=experiment_name, data_analysis_name=data_analysis_name,
    #     file_suffix='destination_analysis_exp1', per_category_suffix='destination_analysis_exp1_per_category'
    # )
    
    update_dataframe(df_exp234, device_list, global_destination_dict_exp234, local_destination_dict_exp234, global_eui64_destination_dict_exp234)
    categorize_and_save_df_to_csv(
        df_exp234, columns, category_index=2, out_dir_tmp=out_dir_tmp,
        experiment_name=experiment_name, data_analysis_name=data_analysis_name,
        file_suffix='destination_analysis_exp234', per_category_suffix='destination_analysis_exp234_per_category'
    )
    
    # # exp56 - IPv6 destination only 
    # update_dataframe(df_exp56, device_list, global_destination_dict_exp56, local_destination_dict_exp56, global_eui64_destination_dict_exp56)
    # categorize_and_save_df_to_csv(
    #     df_exp56, columns, category_index=2, out_dir_tmp=out_dir_tmp,
    #     experiment_name=experiment_name, data_analysis_name=data_analysis_name,
    #     file_suffix='destination_analysis_exp56_ipv6', per_category_suffix='destination_analysis_exp56_ipv6_per_category'
    # )
    
    # ***Destination Comparison Analysis***
    # * Why devices that support all features not working in IPv6-only network?
    # Nest Camera: 80\% of traffic volume in IPv6 but not working in IPv6-only network
    # destination in ipv4-only and dual-stack, but not in ipv6-only
    # 11 devices has global IPv6 data in ipv6-only network but not functional:
    global_ipv6_not_functional_device_ipv6only_network = [
        'samsung-fridge',
        'nest-camera',
        'nest-doorbell',
        'aeotec-hub',
        'smartlife-matter-hub',
        'echoplus',
        'echoshow5',
        'echoshow8',
        'homepod-mini2',
        'firetv',
        'samsungtv65-wifi'
    ]
    ipv4_but_not_ipv6 = {}
    for device in global_ipv6_not_functional_device_ipv6only_network:
        ipv4_but_not_ipv6[device] = ipv4_destination_dict_exp56[device] - global_destination_dict_exp234[device]
    save_json(ipv4_but_not_ipv6, f'{out_dir_tmp}/{experiment_name}_{data_analysis_name}_ipv4_but_not_ipv6.json')
    
    
    # * IPv6 new destinations compared to IPv4 destiantion
    df_v6only = extract_ipv6_only_destinations(
        out_dir_tmp, 
        experiment_name, 
        data_analysis_name, 
        device_list, 
        columns, 
        device_category, 
        global_eui64_destination_dict, 
        ipv4_destination_dict, 
        local_destination_dict_exp1, 
        ipv6_global_destination_dict, 
        ipv6_local_destination_dict
    )
    
    # * IPv4-only destinations in dual stack (exp56): only via IPv4 but not via IPv6
    
    df_v4only_dual_stack, ipv4only_exp56_global_dest = extract_ipv4_only_destinations(
        out_dir_tmp, 
        columns, 
        experiment_name, 
        data_analysis_name, 
        device_list, 
        device_category, 
        global_destination_dict_exp56, 
        ipv4_destination_dict_exp56
    )
    
    # * IPv4-only destinations (in dual stack exp56) for 8 functional devices
    ipv4_only_dest_ipv6onlyfunctional_device(
        out_dir_tmp, experiment_name, data_analysis_name, ipv4only_exp56_global_dest)
    
    # * Dual-stack experiments: communication via IPv4 in IPv4-only choose to use IPv6 in dual-stack. Switch to v6
    df_exp56_switchtov6 = dual_stack_switch_to_ipv6(
        out_dir_tmp,
        columns,
        experiment_name,
        data_analysis_name,
        device_list,
        device_category,
        global_destination_dict_exp1,
        global_destination_dict_exp56,
        ipv4_destination_dict_exp56,
        all_global_destination_dict_exp56
    )
    
    
    # * IPv6 in exp234 but switch to IPv4 in exp56
    df_switchtov4 = dual_stack_switch_to_ipv4(
        out_dir_tmp, 
        columns, 
        experiment_name, 
        data_analysis_name, 
        device_list, 
        device_category, 
        global_destination_dict_exp234, 
        global_destination_dict_exp56, 
        ipv4_destination_dict_exp56
    )
    
    
    # * IPv4 in exp56 but has IPv6 AAAA record
    df_ipv4hybrid_wAAAA = dual_stack_ipv4_with_aaaa_record(
        out_dir_tmp, 
        columns, 
        experiment_name, 
        data_analysis_name, 
        device_list, 
        device_category, 
        ipv6_aaaa_record, 
        global_destination_dict_exp56, 
        ipv4_destination_dict_exp56
    )
    
    
    # * Save to the combined CSV
    df['IPv6 Global Destination'] = [len(ipv6_global_destination_dict[device]) for device in device_list]
    # df['IPv6 Local Destination'] = [len(ipv6_local_destination_dict[device]) for device in device_list]
    df['IPv4 Global Destination'] = [len(ipv4_destination_dict[device]) for device in device_list]
    df['Destination in Dual-stack'] = [len(all_global_destination_dict_exp56[device]) for device in device_list]
    df['Global v4 only in exp56'] = df_v4only_dual_stack['IPv4 only destination in dual-stack' ]
    df['Global v6 only in exp56'] = df_v4only_dual_stack['IPv6 only destination in dual-stack']
    df['IPv6 AAAA Record'] = [len(ipv6_aaaa_record[device]) for device in device_list]
    
    
    df['Global Dest IPv6 not in IPv4'] = df_v6only['Global Destination']
    # df['Local New Dest in exp234 v exp1'] = df_v6only['Local Destination']
    df['Global Dest EUI-64 IPv6 not in IPv4'] = df_v6only['EUI-64 Destination']
    
    # ** Switch to v6 
    df['Global v4 dest partially switch to v6 in exp56'] = df_exp56_switchtov6['Partially switch to v4']
    df['Global v4 dest fully switch to v6 in exp56'] = df_exp56_switchtov6['Fully switch to v4']
    df['Intersection exp1-exp56'] = df_exp56_switchtov6['Intersection exp1-exp56']
    df['IPv4 in exp1 not in exp56'] = df_exp56_switchtov6['IPv4 only in exp1 not exp56']
    df['IPv4 in exp56 not in exp1'] = df_exp56_switchtov6['IPv4 only in exp56 not exp1']
    
    # ** Switch to v4
    # df['Global switch to v6 EUI-64 in exp56'] = df_exp56_switchtov6['EUI-64 Destination']
    df['Global v6 dest partially switch to v4 in exp56'] = df_switchtov4['Partially switch to v4']
    df['Global v6 dest fully switch to v4 in exp56'] = df_switchtov4['Fully switch to v4']
    df['Intersection exp234-exp56'] = df_switchtov4['Intersection exp234-exp56']
    df['IPv6 in exp234 not in exp56'] = df_switchtov4['IPv6 only in exp234 not exp56']
    df['IPv6 in exp56 not in exp234'] = df_switchtov4['IPv6 only in exp56 not exp234']
    
    '''
    IPv4 destinations not contacted in dual stack
    dual-stack IPv4 destinations not contacted in IPv4-only
    IPv6 destinations not contacted in dual stack
    dual-stack IPv6 destinations not contacted in IPv6-only
    '''
    
    # df['Local v4 dest switch to v6 in exp56'] = df_exp56_switchtov6['Local Destination']
    
    
    # Dual-stack IPv4 destinations with AAAA record
    df['Global v4 dest w/ AAAA in exp56'] = df_ipv4hybrid_wAAAA['Global Destination']
    
    
    
    
    df_per_category = convert_to_per_category(df, df.columns, category_index=2)
    df_per_category = add_total_row(df_per_category, index=1)

    
    # ** Calculate fractions
    # Add fraction of partially and fully switch to v6
    calculate_fractions(df_per_category, 'Global v4 dest partially switch to v6 in exp56', 'Intersection exp1-exp56', 'Fraction partially switch to v6')
    calculate_fractions(df_per_category, 'Global v4 dest fully switch to v6 in exp56', 'Intersection exp1-exp56', 'Fraction fully switch to v6')
    
    # Add fraction of partially and fully switch to v4
    calculate_fractions(df_per_category, 'Global v6 dest partially switch to v4 in exp56', 'Intersection exp234-exp56', 'Fraction partially switch to v4')
    calculate_fractions(df_per_category, 'Global v6 dest fully switch to v4 in exp56', 'Intersection exp234-exp56', 'Fraction fully switch to v4')
    
    # Add fraction of v4 dest w/ AAAA in exp56
    calculate_fractions(df_per_category, 'Global v4 dest w/ AAAA in exp56', 'Global v4 only in exp56', 'Fraction v4 dest w/ AAAA in exp56')
    

    # ** Save to CSV
    df_to_csv(df, out_dir_tmp, experiment_name, data_analysis_name, 'destination_analysis_combined')
    df_to_csv(df_per_category, out_dir_tmp, experiment_name, data_analysis_name, 'destination_analysis_per_category_combined')
    df_per_category_T = transpose_df(df_per_category, index_column_name=['Category'])
    df_to_csv(df_per_category_T, out_dir_tmp, experiment_name, data_analysis_name, 'destination_analysis_per_category_combined_T')
    
    
    # ** Prepare for saving to JSON
    ipv6_global_destination_dict_out = {}
    ipv6_local_destination_dict_out = {}
    ipv4_destination_dict_out = {}
    for device in global_destination_dict.keys():
        global_destination_dict[device] = list(global_destination_dict[device])
        local_destination_dict[device] = list(local_destination_dict[device])
        ipv6_global_destination_dict_out[device] = list(ipv6_global_destination_dict[device])
        ipv6_local_destination_dict_out[device] = list(ipv6_local_destination_dict[device])
        ipv4_destination_dict_out[device] = list(ipv4_destination_dict[device])
        all_global_destination_dict_exp56[device] = list(all_global_destination_dict_exp56[device])
        
    # ** Save IPv6 destaintions 

    save_json(ipv6_global_destination_dict_out, f'{out_dir_tmp}/{experiment_name}_{data_analysis_name}_IPv6_global_destination_name_dict.json')
    save_json(ipv6_local_destination_dict_out, f'{out_dir_tmp}/{experiment_name}_{data_analysis_name}_IPv6_local_destination_name_dict.json')
    
    # * Save IPv4 destinations
    save_json(ipv4_destination_dict_out, f'{out_dir_tmp}/{experiment_name}_{data_analysis_name}_IPv4_global_destination_name_dict.json')
        
    # * Save all IPv6 and IPv4 destinations
    save_json(global_destination_dict, f'{out_dir_tmp}/{experiment_name}_{data_analysis_name}_global_destination_name_dict.json')
    save_json(local_destination_dict, f'{out_dir_tmp}/{experiment_name}_{data_analysis_name}_local_destination_name_dict.json')
    

    # * Save all EUI-64 destinations
    for device in global_eui64_destination_dict.keys():
        global_eui64_destination_dict[device] = list(global_eui64_destination_dict[device])
    save_json(global_eui64_destination_dict, f'{out_dir_tmp}/{experiment_name}_{data_analysis_name}_global_eui64_destination.json')
    
    logger.info(f"Destination analysis took {time.time() - start_time} seconds.")
    return

def dual_stack_ipv4_with_aaaa_record(out_dir_tmp, columns, experiment_name, data_analysis_name, device_list, device_category, ipv6_aaaa_record, global_destination_dict_exp56, ipv4_destination_dict_exp56):
    df_ipv4hybrid_wAAAA = initialize_dataframes(columns, device_list, device_category)
    ipv4hybrid_wAAAA_dict = {}
    for device in device_list:
        ipv4hybrid_wAAAA_dict[device] = ipv4_destination_dict_exp56[device].intersection(ipv6_aaaa_record[device]) - global_destination_dict_exp56[device]
    
    ipv4hybrid_wAAAA_out = {}
    for device in device_list:
        ipv4hybrid_wAAAA_out[device] = list(ipv4hybrid_wAAAA_dict[device])
    with open(f'{out_dir_tmp}/{experiment_name}_{data_analysis_name}_ipv4_hybrid_wAAAA_dict.json', 'w') as f:
        json.dump(ipv4hybrid_wAAAA_out, f, indent=4)
    
    df_ipv4hybrid_wAAAA['Global Destination'] = [len(ipv4hybrid_wAAAA_dict[device]) for device in device_list]
    categorize_and_save_df_to_csv(
        df_ipv4hybrid_wAAAA, df_ipv4hybrid_wAAAA.columns, category_index=2, out_dir_tmp=out_dir_tmp,
        experiment_name=experiment_name, data_analysis_name=data_analysis_name,
        file_suffix='destination_analysis_exp56_ipv4_hybrid_wAAAA', per_category_suffix='destination_analysis_exp56_ipv4_hybrid_wAAAA_per_category'
    )
    
    return df_ipv4hybrid_wAAAA

def dual_stack_switch_to_ipv4(out_dir_tmp, columns, experiment_name, data_analysis_name, device_list, device_category, global_destination_dict_exp234, global_destination_dict_exp56, ipv4_destination_dict_exp56):
    df_switchtov4 = initialize_dataframes(columns, device_list, device_category)
    ipv6_switchtov4_partially = {}
    ipv6_switchtov4_fully = {}
    intersection_between_exp234_exp56 = {}
    fraction_fully_switch_to_v4 = {}
    fraction_partially_switch_to_v4 = {}
    ipv6_exp234_not_in_exp56 = {}
    ipv6_exp56_not_in_exp234 = {}
    for device in device_list:
        ipv6_switchtov4_partially[device] = global_destination_dict_exp234[device].intersection(ipv4_destination_dict_exp56[device])
        ipv6_switchtov4_fully[device] = global_destination_dict_exp234[device].intersection(ipv4_destination_dict_exp56[device]) - global_destination_dict_exp56[device]
        ipv6_switchtov4_partially[device] = ipv6_switchtov4_partially[device] - ipv6_switchtov4_fully[device]
        intersection_between_exp234_exp56[device] = global_destination_dict_exp234[device].intersection(global_destination_dict_exp56[device])
        if len(intersection_between_exp234_exp56[device]) != 0:
            fraction_partially_switch_to_v4[device] = len(ipv6_switchtov4_partially[device]) / len(intersection_between_exp234_exp56[device])
            fraction_fully_switch_to_v4[device] = len(ipv6_switchtov4_fully[device]) / len(intersection_between_exp234_exp56[device])
        else:
            fraction_partially_switch_to_v4[device] = 0
            fraction_fully_switch_to_v4[device] = 0
        
        # IPv6 destinations not contacted in dual stack
        ipv6_exp234_not_in_exp56[device] = global_destination_dict_exp234[device] - global_destination_dict_exp56[device]
        
        # dual-stack IPv6 destinations not contacted in IPv6-only
        ipv6_exp56_not_in_exp234[device] = global_destination_dict_exp56[device] - global_destination_dict_exp234[device]
        
    ipv6_switchtov4_out_dict = {}
    for device in device_list:
        ipv6_switchtov4_out_dict[device] = {'Partially':[], 'Fully':[]} # , 'EUI-64':[]
        ipv6_switchtov4_out_dict[device]['Partially'] = list(ipv6_switchtov4_partially[device])
        ipv6_switchtov4_out_dict[device]['Fully'] = list(ipv6_switchtov4_fully[device])

    with open(f'{out_dir_tmp}/{experiment_name}_{data_analysis_name}_switch_to_v4_dict.json', 'w') as f:
        json.dump(ipv6_switchtov4_out_dict, f, indent=4)
    
    df_switchtov4['Partially switch to v4'] = [len(ipv6_switchtov4_partially[device]) for device in device_list]
    df_switchtov4['Fully switch to v4'] = [len(ipv6_switchtov4_fully[device]) for device in device_list]
    df_switchtov4['Intersection exp234-exp56'] = [len(intersection_between_exp234_exp56[device]) for device in device_list]
    df_switchtov4['Fraction partially switch to v4'] = [fraction_partially_switch_to_v4[device] for device in device_list]
    df_switchtov4['Fraction fully switch to v4'] = [fraction_fully_switch_to_v4[device] for device in device_list]
    df_switchtov4['IPv6 only in exp234 not exp56'] = [len(ipv6_exp234_not_in_exp56[device]) for device in device_list]
    df_switchtov4['IPv6 only in exp56 not exp234'] = [len(ipv6_exp56_not_in_exp234[device]) for device in device_list]
    
    categorize_and_save_df_to_csv(
        df_switchtov4, df_switchtov4.columns, category_index=2, out_dir_tmp=out_dir_tmp,
        experiment_name=experiment_name, data_analysis_name=data_analysis_name,
        file_suffix='destination_analysis_exp234_exp56_switch_to_v4', per_category_suffix='destination_analysis_exp234_exp56_switch_to_v4_per_category'
    )
    
    return df_switchtov4

def dual_stack_switch_to_ipv6(out_dir_tmp, columns, experiment_name, data_analysis_name, device_list, device_category, global_destination_dict_exp1, global_destination_dict_exp56, ipv4_destination_dict_exp56, all_global_destination_dict_exp56):
    df_exp56_switchtov6 = initialize_dataframes(columns, device_list, device_category)
    ipv6hybrid_global_dest_in_exp1 = {}
    ipv6hybrid_global_dest_nov4_in_exp1 = {}
    # ipv6hybrid_local_dest_in_exp1 = {}
    ipv6hybrid_eui64_dest_in_exp1 = {}
    intersection_between_exp1_exp56 = {}
    fraction_partially_switch_to_v6 = {}
    fraction_fully_switch_to_v6 = {}
    ipv4_exp1_not_in_exp56 = {}
    ipv4_exp56_not_in_exp1 = {}
    
    for device in device_list:
        ipv6hybrid_global_dest_in_exp1[device] = global_destination_dict_exp56[device].intersection(global_destination_dict_exp1[device]) 
        ipv6hybrid_global_dest_nov4_in_exp1[device] = global_destination_dict_exp56[device].intersection(global_destination_dict_exp1[device]) - ipv4_destination_dict_exp56[device]
        ipv6hybrid_global_dest_in_exp1[device] = ipv6hybrid_global_dest_in_exp1[device] - ipv6hybrid_global_dest_nov4_in_exp1[device]
        # ipv6hybrid_local_dest_in_exp1[device] = local_destination_dict_exp56[device].intersection(local_destination_dict_exp1[device])
        # ipv6hybrid_eui64_dest_in_exp1[device] = global_eui64_destination_dict_exp56[device].intersection(global_destination_dict_exp1[device])
        intersection_between_exp1_exp56[device] = all_global_destination_dict_exp56[device].intersection(global_destination_dict_exp1[device])
        
        
        # ** fraction of IPv4 destinations switch to IPv6
        if len(intersection_between_exp1_exp56[device]) != 0:
            fraction_partially_switch_to_v6[device] = len(ipv6hybrid_global_dest_in_exp1[device]) / len(intersection_between_exp1_exp56[device])
            fraction_fully_switch_to_v6[device] = len(ipv6hybrid_global_dest_nov4_in_exp1[device]) / len(intersection_between_exp1_exp56[device])
        else:
            fraction_partially_switch_to_v6[device] = 0  
            fraction_fully_switch_to_v6[device] = 0
        
        # ** IPv4 destinations not contacted in dual stack
        ipv4_exp1_not_in_exp56[device] = global_destination_dict_exp1[device] - ipv4_destination_dict_exp56[device]
        
        # ** dual-stack IPv4 destinations not contacted in IPv4-only
        ipv4_exp56_not_in_exp1[device] = ipv4_destination_dict_exp56[device] - global_destination_dict_exp1[device]
        
    ipv6hybrid_out_dict = {}
    for device in device_list:
        ipv6hybrid_out_dict[device] = {'Partially':[], 'Fully':[]} # , 'EUI-64':[]
        ipv6hybrid_out_dict[device]['Partially'] = list(ipv6hybrid_global_dest_in_exp1[device])
        ipv6hybrid_out_dict[device]['Fully'] = list(ipv6hybrid_global_dest_nov4_in_exp1[device])
        # ipv6hybrid_out_dict[device]['Local'] = list(ipv6hybrid_local_dest_in_exp1[device])
        # ipv6hybrid_out_dict[device]['EUI-64'] = list(ipv6hybrid_eui64_dest_in_exp1[device])
    with open(f'{out_dir_tmp}/{experiment_name}_{data_analysis_name}_switch_to_v6_dict.json', 'w') as f:
        json.dump(ipv6hybrid_out_dict, f, indent=4)
        
    df_exp56_switchtov6['Partially switch to v4'] = [len(ipv6hybrid_global_dest_in_exp1[device]) for device in device_list]
    df_exp56_switchtov6['Fully switch to v4'] = [len(ipv6hybrid_global_dest_nov4_in_exp1[device]) for device in device_list]
    # df_exp56_switchtov6['Local Destination'] = [len(ipv6hybrid_local_dest_in_exp1[device]) for device in device_list]
    # df_exp56_switchtov6['EUI-64 Destination'] = [len(ipv6hybrid_eui64_dest_in_exp1[device]) for device in device_list]
    df_exp56_switchtov6['Intersection exp1-exp56'] = [len(intersection_between_exp1_exp56[device]) for device in device_list]
    df_exp56_switchtov6['Fraction partially switch to v6'] = [fraction_partially_switch_to_v6[device] for device in device_list]
    df_exp56_switchtov6['Fraction fully switch to v6'] = [fraction_fully_switch_to_v6[device] for device in device_list]
    
    df_exp56_switchtov6['IPv4 only in exp1 not exp56'] = [len(ipv4_exp1_not_in_exp56[device]) for device in device_list]
    df_exp56_switchtov6['IPv4 only in exp56 not exp1'] = [len(ipv4_exp56_not_in_exp1[device]) for device in device_list]
    
    categorize_and_save_df_to_csv(
        df_exp56_switchtov6, df_exp56_switchtov6.columns, category_index=2, out_dir_tmp=out_dir_tmp,
        experiment_name=experiment_name, data_analysis_name=data_analysis_name,
        file_suffix='destination_analysis_exp56_exp1_switch_to_v6', per_category_suffix='destination_analysis_exp56_exp1_switch_to_v6_per_category'
    )
    
    return df_exp56_switchtov6

def ipv4_only_dest_ipv6onlyfunctional_device(out_dir_tmp, experiment_name, data_analysis_name, ipv4only_exp56_global_dest):
    ipv6_only_functionaly_devices = ['facebook-portal-mini', 'google-home-mini', 'google-nest-mini1', 'nest-hub', 'nest-hub-max', 'appletv', 'chromecast-googletv', 'tivostream']
    ipv4_only_dest_ipv6functional_dict = {}
    for device in ipv6_only_functionaly_devices:
        ipv4_only_dest_ipv6functional_dict[device] = {}
        ipv4_only_dest_ipv6functional_dict[device] = list(ipv4only_exp56_global_dest[device])
        
    save_json(ipv4_only_dest_ipv6functional_dict, f'{out_dir_tmp}/{experiment_name}_{data_analysis_name}_ipv4_only_dest_ipv6functional_dict.json')
    ipv6_only_functionaly_df = pd.DataFrame(columns=['Device', 'IPv4 Only Destination'])
    ipv6_only_functionaly_df['Device'] = ipv6_only_functionaly_devices
    ipv6_only_functionaly_df['IPv4 Only Destination'] = [len(ipv4only_exp56_global_dest[device]) for device in ipv6_only_functionaly_devices]
    df_to_csv(ipv6_only_functionaly_df, out_dir_tmp, experiment_name, data_analysis_name, 'destination_analysis_ipv4_only_ipv6_functional_devices')

def extract_ipv4_only_destinations(out_dir_tmp, columns, experiment_name, data_analysis_name, device_list, device_category, global_destination_dict_exp56, ipv4_destination_dict_exp56):
    df_v4only_dual_stack = initialize_dataframes(columns, device_list, device_category)
    
    ipv4only_exp56_global_dest = {}
    ipv6only_exp56 = {}
    ipv4only_only_local_dest = {}
    for device in device_list:
        # ipv4only_exp56_global_dest[device] = ipv4_destination_dict[device] - ipv6_global_destination_dict[device]
        ipv4only_exp56_global_dest[device] = ipv4_destination_dict_exp56[device] - global_destination_dict_exp56[device]
        ipv6only_exp56[device] = global_destination_dict_exp56[device] - ipv4_destination_dict_exp56[device]
        
    ipv4only_only_out_dict = {}
    for device in device_list:
        ipv4only_only_out_dict[device] = list(ipv4only_exp56_global_dest[device])
        # ipv4only_only_out_dict[device]['Local'] = list(ipv4only_only_local_dest[device])
    with open(f'{out_dir_tmp}/{experiment_name}_{data_analysis_name}_hybrid_ipv4_only_dest_dict.json', 'w') as f:
        json.dump(ipv4only_only_out_dict, f, indent=4)
    
    df_v4only_dual_stack['IPv4 only destination in dual-stack'] = [len(ipv4only_exp56_global_dest[device]) for device in device_list]
    df_v4only_dual_stack['IPv6 only destination in dual-stack'] = [len(ipv6only_exp56[device]) for device in device_list]
    # df_v4only_dual_stack['Local Destination'] = [len(ipv4only_only_local_dest[device]) for device in device_list]
    categorize_and_save_df_to_csv(
        df_v4only_dual_stack, df_v4only_dual_stack.columns, category_index=2, out_dir_tmp=out_dir_tmp,
        experiment_name=experiment_name, data_analysis_name=data_analysis_name,
        file_suffix='destination_analysis_hybrid_ipv4_only', per_category_suffix='destination_analysis_hybrid_ipv4_only_per_category'
    )
    
    return df_v4only_dual_stack, ipv4only_exp56_global_dest


def extract_ipv6_only_destinations(out_dir_tmp, experiment_name, data_analysis_name, device_list, columns, device_category, global_eui64_destination_dict, ipv4_destination_dict, local_destination_dict_exp1, ipv6_global_destination_dict, ipv6_local_destination_dict):
    df_v6only = initialize_dataframes(columns, device_list, device_category)
    ipv6only_only_global_dest = {}
    ipv6only_only_local_dest = {}
    ipv6only_eui64_new_dest = {}    # EUI64 dest not contacted by IPv4
    for device in device_list:
        # ipv6only_only_global_dest[device] = global_destination_dict_exp234[device] - global_destination_dict_exp1[device]
        ipv6only_only_global_dest[device] = ipv6_global_destination_dict[device] - ipv4_destination_dict[device]
        ipv6only_only_local_dest[device] = ipv6_local_destination_dict[device] - local_destination_dict_exp1[device] # limitation, no exp56 local destination 
        ipv6only_eui64_new_dest[device] = global_eui64_destination_dict[device] - ipv4_destination_dict[device]
    
    ipv6only_only_out_dict = {}
    for device in device_list:
        ipv6only_only_out_dict[device] = {'Global':[], 'Local':[], 'EUI-64':[]}
        ipv6only_only_out_dict[device]['Global'] = list(ipv6only_only_global_dest[device])
        ipv6only_only_out_dict[device]['Local'] = list(ipv6only_only_local_dest[device])
        ipv6only_only_out_dict[device]['EUI-64'] = list(ipv6only_eui64_new_dest[device])
    with open(f'{out_dir_tmp}/{experiment_name}_{data_analysis_name}_ipv6_only_dest_dict.json', 'w') as f:
        json.dump(ipv6only_only_out_dict, f, indent=4)
        
    df_v6only['Global Destination'] = [len(ipv6only_only_global_dest[device]) for device in device_list]
    df_v6only['Local Destination'] = [len(ipv6only_only_local_dest[device]) for device in device_list]
    df_v6only['EUI-64 Destination'] = [len(ipv6only_eui64_new_dest[device]) for device in device_list]
    # df_v6only_per_category = convert_to_per_category(df_v6only, df_v6only.columns, category_index=2)
    # df_v6only_per_category = add_total_row(df_v6only_per_category, index=1)
    # df_to_csv(df_v6only, out_dir_tmp, experiment_name, data_analysis_name, 'destination_analysis_ipv6_only')
    # df_to_csv(df_v6only_per_category, out_dir_tmp, experiment_name, data_analysis_name, 'destination_analysis_ipv6_only_per_category')
    categorize_and_save_df_to_csv(
        df_v6only, df_v6only.columns, category_index=2, out_dir_tmp=out_dir_tmp,
        experiment_name=experiment_name, data_analysis_name=data_analysis_name,
        file_suffix='destination_analysis_ipv6_only', per_category_suffix='destination_analysis_ipv6_only_per_category'
    )
    return df_v6only

def categorize_and_save_df_to_csv(df, columns, category_index, out_dir_tmp, experiment_name, data_analysis_name, file_suffix, per_category_suffix):
    """
    Process the DataFrame by converting to per category, adding a total row, and saving to CSV.
    
    Parameters:
    - df: The DataFrame to process.
    - columns: The columns to use for processing.
    - category_index: The index of the category column.
    - out_dir_tmp: The output directory.
    - experiment_name: The name of the experiment.
    - data_analysis_name: The name of the data analysis.
    - file_suffix: The suffix for the main CSV file.
    - per_category_suffix: The suffix for the per category CSV file.
    """
    df_per_category = convert_to_per_category(df, columns, category_index=category_index)
    df_per_category = add_total_row(df_per_category, index=1)
    df_to_csv(df, out_dir_tmp, experiment_name, data_analysis_name, file_suffix)
    df_to_csv(df_per_category, out_dir_tmp, experiment_name, data_analysis_name, per_category_suffix)
    
def initialize_dataframes(columns, device_list, device_category):
    df = pd.DataFrame(columns=columns)
    df['Device'] = device_list
    df['Category'] = [device_category[device] for device in device_list]
    return df
