#!/usr/bin/env python3
from __future__ import print_function
import socket
import argparse
import requests
import re


parser = argparse.ArgumentParser(description='Enumerate subdomains via certificate transparency logs')
parser.add_argument('domain', type=str, help='Target domain name')
parser.add_argument('-i', action='count', default=0, help='Enables printing of hosts believed to be internal only')
parser.add_argument('--expired', action='count', default=0, help='Ignores expired certificates')
parser.add_argument('-v', action='count', help='Enables verbose output, -v for verbose or -vv for very verbose',
                        default=0)

args = parser.parse_args()

target_domain = args.domain
verbose = args.v
internal_hosts = []

if args.expired:
    r = requests.get('https://crt.sh/?q=%.'+target_domain+'&exclude=expired')
else:
    r = requests.get('https://crt.sh/?q=%.'+target_domain)
hostnames = re.findall(r'<TD>(\S+\.'+target_domain+r')',r.text)
uniq_hostnames = set(hostnames)
if verbose:
    print('Domain names found:')
    for host in uniq_hostnames:
        print(host)

for host in uniq_hostnames:
    try:
        data = socket.gethostbyname_ex(host)
        print(data[0]+'\t'+data[2][0])
    except socket.gaierror:
        if verbose:
            print('{host} does not resolve, may be resolveable internally only'.format(host=host))
        internal_hosts.append(host)


if args.i:
    print('\n\nHostnames exist in certificate transparancy logs, but do not resolve')
    for host in internal_hosts:
        print(host)


