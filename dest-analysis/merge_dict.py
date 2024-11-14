import pickle
import os
import json

# output dir 
out_dir = 'output'
if not os.path.exists(out_dir):
    exit(1)
    os.system(f'mkdir -pv {out_dir}')
ip_hosts_all = {}
domain_list_all = {}

for exp in ['exp234' , 'exp56', 'exp1']:
    model_file = f"{out_dir}/{exp}_ip_hosts_all.model"
    model_file2 = f"{out_dir}/{exp}_domain_list_all.model"
    ip_hosts_exp = pickle.load(open(model_file, 'rb'))
    domain_list_exp = pickle.load(open(model_file2, 'rb'))


    for dev in domain_list_exp:
        domain_list_all[dev] =  domain_list_all.setdefault(dev, set()).union(domain_list_exp[dev])
    for dev in ip_hosts_exp:
        ip_hosts_all[dev] = ip_hosts_all.get(dev, {})
        for ip in ip_hosts_exp[dev]:
            ip_hosts_all[dev][ip] = ip_hosts_exp[dev][ip]

pickle.dump(ip_hosts_all, open(f"{out_dir}/all_ip_hosts_all.model", 'wb'))
pickle.dump(domain_list_all, open(f"{out_dir}/all_domain_list_all.model", 'wb'))


count = 0
for dev in domain_list_all:

    domain_list_all[dev] = list(domain_list_all[dev])
    count += len(list(domain_list_all[dev]))
json.dump(domain_list_all, open(f"{out_dir}/all_domain_list_all.json", 'w'))
print('Domain Count: ', count)