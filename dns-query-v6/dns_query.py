import dns.resolver
import dns.exception
import json
import concurrent.futures
import csv
import os
from ratelimiter import RateLimiter

def query_domain(device, domain, resolver):
    with resolver['limiter']:
        try:
            # Get the IPv6 address
            # https://dnspython.readthedocs.io/en/latest/resolver-class.html#dns.resolver.Answer
            answer = resolver['resolver'].resolve(domain, 'AAAA') # 'A'
            if answer:
                ipv6_address = ';'.join([rr.to_text() for rr in answer.rrset])
                canonical_name = answer.canonical_name.to_text()
                return (device, domain, ipv6_address, 'no error AAAA response', canonical_name, resolver['resolver'].nameservers[0])
            else:
                if answer.response:
                    return (device, domain, 'No AAAA answer received', 'No AAAA answer received', answer.response.to_text(), resolver['resolver'].nameservers[0])
                else:
                    return (device, domain, 'No AAAA answer received', 'No AAAA answer received', None , resolver['resolver'].nameservers[0])
        except dns.resolver.NoAnswer:
            return (device, domain, 'No AAAA answer received', 'No AAAA answer received', None, resolver['resolver'].nameservers[0])
        except dns.resolver.NXDOMAIN:
            return (device, domain, 'Domain does not exist', 'Domain does not exist', None, resolver['resolver'].nameservers[0])
        except dns.resolver.NoNameservers:
            return (device, domain, 'Nameservers failed to answer', 'Nameservers failed to answer', None, resolver['resolver'].nameservers[0])
        except dns.exception.Timeout:
            return (device, domain, 'Query timed out', 'Query timed out', None, resolver['resolver'].nameservers[0])
        except Exception as e:
            return (device, domain, str(e), 'others', None, resolver['resolver'].nameservers[0])

# Load the JSON file
with open('../dest-analysis/output/all_domain_list_all.json', 'r') as f:
# with open('all_domain_list_all.json', 'r') as f:
    devices = json.load(f)

devices = {k: v for k, v in devices.items()}
print(devices)

# Specify the DNS resolvers
resolvers = [{'resolver': dns.resolver.Resolver(configure=False), 'limiter': RateLimiter(max_calls=5, period=1)} for _ in range(2)]
resolvers[0]['resolver'].nameservers = ['8.8.8.8']  # Google DNS    2001:4860:4860::8888
resolvers[1]['resolver'].nameservers = ['2001:4860:4860::8888']  # Google DNS    2001:4860:4860::8888
# resolvers[0]['resolver'].nameservers = ['208.67.222.222']  # OpenDNS    2620:0:ccc::2
# resolvers[1]['resolver'].nameservers = ['1.1.1.1']  # Cloudflare DNS    2606:4700:4700::1111
# resolvers[3]['resolver'].nameservers = ['223.6.6.6'] # AliDNS   2400:3200::1
# resolvers[4]['resolver'].nameservers = ['155.33.33.75'] # NEU DNS 

# Initialize a dictionary to store the responses
responses = {device: [] for device in devices}

# Prepare the tasks
tasks = [(device, domain, resolver) for device in devices for domain in devices[device] for resolver in resolvers]

# Execute the tasks
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:  # Limit the number of concurrent threads
    future_to_query = {executor.submit(query_domain, device, domain, resolver): (device, domain, resolver) for device, domain, resolver in tasks}
    for future in concurrent.futures.as_completed(future_to_query):
        device, domain, resolver = future_to_query[future]
        response_device, response_domain, response, response_type, canoical_name, nameserver = future.result()
        responses[device].append((response_domain, nameserver, response_type, response, canoical_name))

# Save the responses in CSV files
if not os.path.exists('output'):
    os.makedirs('output')
for device, response_list in responses.items():
    with open(f'output/{device}.csv', 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Domain', 'Resolver', 'Response Type', 'Response', 'Canonical Name'])
        for domain, resolver, response_type, response, canoical_name in response_list:
            writer.writerow([domain, resolver, response_type, response, canoical_name])