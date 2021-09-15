#!/usr/bin/python
# This will need the investigate module installed via 'pip install investigate'
import investigate, json, fileinput, codecs, sys, os, requests, time, re
from math import ceil

def slice(l, n):
    n = max(1, n)
    return [l[i:i + n] for i in range(0, len(l), n)]

# Read key, single line
with open('api-key.txt', 'r') as k:
    api_key = k.read().rstrip()
newdata={}
inv = investigate.Investigate(api_key)

# Initialize vars

domains=[]
hitcount={}

if len(sys.argv) == 2:
    filename = sys.argv[1]
else:
    print('ERROR: please provide an input file name')
    sys.exit(1)

with open(filename) as f:
    for line in f:
        # Sanitize the input if possible. No protocols, no URLs just hostnames
        line=line.replace('\n', '')
        linedomain=line.split(',')[0].strip('\n')
        linedomain=re.sub(r'\"', '', linedomain)
        linedomain=re.sub(r'^http\:\/\/', '', linedomain)
        linedomain=re.sub(r'^https\:\/\/', '', linedomain)
        linedomain=re.sub(r'\:.*$', '', linedomain)
        linedomain=re.sub(r'\/.*$', '', linedomain)
        # hitcount[linedomain]=line.split(',')[2].strip('\n')

        # Single word domain isn't valid
        if linedomain.find('.')!=-1:
            if linedomain not in domains:
                domains.append(linedomain)

# How many chunks do we need?
size = len(domains)
chunks = int(ceil(size/1000))

# Take care of any remainder
# if (size%1000): chunks=chunks+1
slices=slice(domains,1000)
print('Domains:', size,'Chunks:', chunks)

# Print first line of CSV output

# print('Destination,Hit Count,Content Category,Security Category,Blocked Since')
print('Destination,Content Category,Security Category,Blocked Since')

for chunk in range(0, chunks):
    # Call to Investigate bulk endpoint
    results = inv.categorization(slices[chunk], labels=True)

    for domain, value in results.items():
        # Some of the domains in the file may be unicode
        domain=domain.encode('utf-8')

        # Delink the domains on output
        domain_safe=domain.split('.')
        domain_end=domain_safe[-1]
        domain_safe=domain_safe[:-1]
        sys.stdout.write('.'.join(domain_safe))
        sys.stdout.write('[.]'+domain_end)
        sys.stdout.write(',')

        # sys.stdout.write(str(hitcount[domain])+',')

        # This returns content_categories, security_categories, and status.
        # The status we don't care about here. Walk through and get the results.
        for category, categories in value.items():
            if category == 'content_categories':
                sys.stdout.write('|'.join(str(p) for p in categories))
                sys.stdout.write(',')
            if category == 'security_categories':
                if not categories:
                    sys.stdout.write('Benign')
                    print
                else:
                    sys.stdout.write('|'.join(str(p) for p in categories))
                    auth_header = auth_header={'Authorization':'Bearer ' + api_key}
                    r = requests.get('https://investigate.api.umbrella.com/timeline/' + domain, headers=auth_header)
                    result = json.loads(r.text)
                    try:
                        timestamp = result[ 0 ]['timestamp']
                        print( ',' + time.strftime('%Y-%m-%d', time.localtime(timestamp/1000)))
                    except:
                        print( ',' + str( result ))
                    sys.stdout.flush()
