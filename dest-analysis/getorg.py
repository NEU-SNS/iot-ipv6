import whois
from ipwhois import IPWhois
import whoisdomain
import ipaddress
import pandas as pd
import numpy as np
import os 
import csv
import json
import time
import subprocess

"""
This script is used to get the organization and classify owner's party of the destination domain using WHOIS data. 
Input: file_list: list of json files with domain names
Output: CSV files with columns: device, domain, org, party

get_organization_new, get_organization, get_organization_info are three methods to get WHOIS data. WHOIS data is not always available through one method. 
"""

def is_valid_ip(i):
    try:
        ipaddress.ip_address(i)
        if i.startswith('192.168.') or i.startswith('224.') or i.startswith('239.') or i.startswith('169.254') or i.startswith('multicast'):
            return False
        return True
    except ValueError:
        return False

def get_organization_ip(ip):
    try:
        ip_whois = IPWhois(ip)
        result = ip_whois.lookup_rdap()
    except:
        return None
    # print(result.keys())
    organizations = set()
    
    
    if 'objects' in result:
        objects = result['objects']
        
        for object in objects:
            if object in objects:
                if 'contact' in objects[object]:
                    if 'organization' in objects[object]['contact']:
                        organizations.add(objects[object]['contact']['organization'])
                    elif 'name' in objects[object]['contact']:
                        organizations.add(objects[object]['contact']['name'])
                else:
                    organizations.add(object)
        print(organizations)
        return list(organizations)

    if 'entities' in result:
        entities = result['entities']
        
        # print(entities)
        print(entities)
        for entity in entities:
            # if 'roles' in entity and 'registrant' in entity['roles']:
            if 'contact' in entity:
                if 'organization' in entity['contact']:
                    organizations.add(entity['contact']['organization'])
                elif 'name' in entity['contact']:
                    organizations.add(entity['contact']['name'])
            else:
                organizations.add(entity)
        return list(organizations)

    return None

def get_whois_data(domain):
    try:
        result = subprocess.run(['whois', domain], stdout=subprocess.PIPE)
        return result.stdout.decode()
    except:
        return None

def get_organization_info(domain):
    whois_data = get_whois_data(domain)
    if whois_data:
        org_list = []
        for line in whois_data.split("\n"):
            if 'Organization' in line.strip() or 'OrgName' in line.strip():
                org = line.split(":")[1].strip()
                if 'Data Protected' in org or 'Domains By Proxy' in org or 'REDACTED' in org or 'Not Disclosed' in org:
                    continue
                org_list.append(org)
        # print(domain, org_list)
        if len(org_list) > 0:
            return org_list
        else:
            return None

    return None



def get_organization(domain):
    w = whois.whois(domain)
    # if domain == 'a2z.com':
    
    if w and 'org' in w:
        print(domain, w['org'])
        organization = w['org']
        # print(organization)
        if isinstance(organization, str):
            return [organization]
        elif isinstance(organization, list):
            if 'Data Protected' in organization or 'Domains By Proxy' in organization or 'REDACTED' in organization or 'Not Disclosed' in organization:
                return None
            return organization

    return None

def get_organization_new(domain):
    try:
        w = whoisdomain.query(domain).__dict__
    except:
        return None
    if w and 'registrant' in w:
        print(domain, w['registrant'])
        organization = w['registrant']
        # print(organization)
        if isinstance(organization, str):
            return [organization]
        elif isinstance(organization, list):
            if 'Data Protected' in organization or 'Domains By Proxy' in organization or 'REDACTED' in organization or 'Not Disclosed' in organization:
                return None
            return organization

    return None



def read_input(file):
    data = pd.read_csv(file)
    hosts = np.array(data['hosts'].fillna('').values)
    return hosts


def read_first_party(file):
    device_first_party = {}
    
    with open(file, 'r') as f:
        lines = f.readlines()
        for line in lines:
            if line:
                device = line.split()[0]
                first_party = line.split()[1:]
                device_first_party[device] = first_party
    return device_first_party


def process_single(input_string, device_first_party, domain_org_dict):
    
    # input_string = 'compute.amazonaws.com'
    
    # if input_string != "amcs-tachyon.com":
    #     return 0, 0
    # print('---', input_string)
    save_org = None
    if is_valid_ip(input_string):
        print('Input IP: ', input_string)
        # return None, None, None
        if input_string in domain_org_dict:
            organization = [domain_org_dict[input_string]]
            save_org = -1
        else:
            organization = get_organization_info(input_string)
            """
            Sometimes one method doesn't work, so we can try the other method
            or get_organization(input_string)
            or get_organization_new(input_string)
            """
    else:  
        input_string = '.'.join(input_string.split('.')[-2:])
        if input_string in domain_org_dict:
            
            organization = [domain_org_dict[input_string]]
            save_org = -1
            # print(input_string, organization)
        else:
            organization = get_organization_info(input_string)

    
    if organization and save_org != -1:
        save_org = organization[0]
        organization.append(input_string)
        # print(f"Organization for {input_string}: {organization}")
    elif save_org == -1:
        save_org = None
        # organization = input_string
    else:
        if input_string in ['amcs-tachyon.com', 'cloudfront.net', 'a2z.com', 'fireoscaptiveportal.com']:
            organization = ['Amazon Technologies, Inc.']
        else:
            organization = ['.'.join(input_string.split('.')[-2:])]
        # print(f"Organization not found for {input_string}")
    # print('Second org: ', organization)
    party = 0
    support_party_list = ['aws', 'cloudflare' , 'amazon', 'org', 'neu.edu', 'aka','digicert', 'Wikimedia']
    if not isinstance(organization, list):
        print('error:', organization, input_string)
    # print(input_string, organization)
    for first_party in device_first_party:
        first_party = first_party.strip().lower()

        for org in organization:
            # if first_party=='google':
            #     print(org, first_party in org)
            if first_party in org.lower():
                
                party = 1
                organization = org
                break
        else:
            continue
    if party != 1:
        for org in organization:
            for s in support_party_list:
                if s in org.lower():
                    party = 2
                    organization = org
                    break
            else:
                continue
    if party == 0:
        party = 3
        organization = organization[0]
    # print('Party: ', party)
    return organization, party, save_org

first_party_list = 'first_party_list.txt'

file_list = ['sample_getorg_input/destination_ipv4_hybrid_wAAAA.json']

for file in file_list:
    if not os.path.exists(file):
        print('------------------------------File not found:', file)
        continue
    with open(file, 'r') as f:
        data = json.load(f)
    # device_first_party = read_first_party(first_party_list)

            

    # Remove keys with empty values
    if 'Global' in data[list(data.keys())[0]]:
        data = {k: v['Global'] for k, v in data.items() if v['Global']}
    elif 'Partially' in data[list(data.keys())[0]]:
        data = {k: list(set(v['Partially'] + v['Fully'])) for k, v in data.items() if v['Partially']}
    else:
        data = {k: v for k, v in data.items() if v}
        
    # Merge devices with multiple interfaces (MAC addresses)
    if 'appletv' in data and 'appletv-wifi' in data:
        data['appletv'] = list(set(data['appletv'] + data['appletv-wifi']  ))
        del data['appletv-wifi']
    elif 'appletv-wifi' in data:
        data['appletv'] = data['appletv-wifi']
        del data['appletv-wifi']
    if 'samsungtv65-wifi' in data and 'samsungtv65-wired' in data:
        data['samsungtv65-wifi'] = list(set(data['samsungtv65-wifi'] + data['samsungtv65-wired']  ))
        del data['samsungtv65-wired']
    elif 'samsungtv65-wired' in data:
        data['samsungtv65-wifi'] = data['samsungtv65-wired']
        del data['samsungtv65-wired']
    if 'sengled-hub' in data and 'sengled-hub-spoofed' in data:
        data['sengled-hub'] = list(set(data['sengled-hub'] + data['sengled-hub-spoofed']  ))
        del data['sengled-hub-spoofed']
    elif 'sengled-hub-spoofed' in data:
        data['sengled-hub'] = data['sengled-hub-spoofed']
        del data['sengled-hub-spoofed']
        
        
    out_dir = 'destination_party'
    output_file = os.path.basename(file).split('.')[0]
    if not os.path.exists(out_dir):
        os.system('mkdir -pv %s' % out_dir)

    header = ['device', 'domain', 'org', 'party']
    if os.path.isfile('domain_org_dict.json'):
        domain_org_dict = json.load(open('domain_org_dict.json','r'))
    else:
        domain_org_dict = {}
    device_first_party = read_first_party(first_party_list)
    for key in data:
        if key not in device_first_party:
            print('Error:', key)

    tmp_output = []
    for device_name in data:
        if device_name not in device_first_party:
            continue
        #     continue
        
        # print(device_name, device_first_party[device_name])
        for domain in data[device_name]:
            organization, party, save_org = process_single(domain, device_first_party[device_name], domain_org_dict)
            tmp_output.append([ device_name, domain, organization, party])
            if save_org:
                if not is_valid_ip(domain):
                    tmp_domain = '.'.join(domain.split('.')[-2:])
                else:
                    tmp_domain = domain
                if tmp_domain not in domain_org_dict:
                    domain_org_dict[tmp_domain] = save_org
                    json.dump(domain_org_dict, open('domain_org_dict.json', 'w'), indent=4)



    with open(os.path.join(out_dir, f'{output_file}.csv'), 'w') as file:
        writer = csv.writer(file)
        writer.writerow(header)
        writer.writerows(tmp_output)
                

    print('Done:', output_file)
    print('-----------------------------------')
