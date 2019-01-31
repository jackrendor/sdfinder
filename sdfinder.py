#!/usr/bin/env python3

import dns.resolver
import requests
from hashlib import sha224
from sys import argv
import threading
import urllib3
from time import sleep
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DNS_LIST = ['8.8.8.8','8.8.4.4','1.1.1.1', '1.0.0.1']
COLLECTED_HASH = []

OK = " \033[7;49;32m[OK]\033[0m"
CHECKSSITE = "\033[2;40;34m<- Check\033[0m"

def get_sha(text=None):
    return sha224(text.encode('utf-8')).hexdigest()

def get_data(dns_result):
    data_s = ""
    for d in dns_result:
        data_s += "%s, "%d
    return data_s[:-2]
def get_subdomain(filename=None):
    with open(filename, "r") as fd:
        yield None
        for line in fd:
            yield line.rstrip()

def EXIT():
    print("\n\033[7;107;31mEXITING...\033[0m\n\n")
    exit(-1)

def query(res=None,  domain=None):
    try:
        result = res.query(domain, "A")
        return True, result
    except KeyboardInterrupt:
        EXIT()
    except Exception:
        #print(" [FAILED]", domain, end=" \n")
        return False, None

def req(resolver, session, target, subdomain=None):
    global COLLECTED_HASH
    if subdomain:
        target = "%s.%s" % (subdomain, target)
    success, data = query(resolver, target)
    
    if not success:
        return
    
    data_ip = get_data(data)
    try:
        r = session.get("http://%s" % target, verify=False)
        hash_site = get_sha(r.text)
        if hash_site not in COLLECTED_HASH:
            COLLECTED_HASH.append(hash_site)
            print(OK, target, data_ip, r.status_code, CHECKSSITE)
        else:
            print(OK, target, data_ip, r.status_code)
    except KeyboardInterrupt:
        EXIT()
    except Exception as err:
        print(OK, target, data_ip, "<- No webserver ", err)

def main():
    if len(argv) < 3:
        print("Usage:\n %s <dictionary of subdomains> <starting domain>" % argv[0])
        exit(1)
    filename = argv[1]
    target = argv[2]
    
    resolver = dns.resolver.Resolver()
    resolver.nameservers = DNS_LIST
    
    # Create a session for sending http requests
    session = requests.Session()
    # Sending first request to get the "default" website
    try:
        r = session.get("http://%s"%target, verify=False)
    except KeyboardInterrupt:
        EXIT()
    
    global COLLECTED_HASH
    # Add the hash of the result to the list
    COLLECTED_HASH.append(get_sha(r.text))
    try:
        for sub in get_subdomain(filename):
            #req(resolver, session, target, sub)
            sleep(0.5)
            threading.Thread(target=req, args=(resolver, session, target, sub)).start()
    except KeyboardInterrupt:
        EXIT()


if __name__ == "__main__":
    main()
