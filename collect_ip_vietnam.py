#!/usr/bin/env python
#
# Collect public IP addresses (IPv4 and IPv6) in Vietnam

from datetime import datetime
from pprint import pformat

import sys
import re

try:
    import requests
except ImportError:
    with open("/home/hoangtnk/Logs/collect_ip_vietnam.log", "a") as f:
        f.write(datetime.now().strftime("%d/%m/%Y %H:%M:%S") + ": Fatal error! Requests module has not been installed!\n")
    sys.exit()

try:
    from ipaddress import ip_network
except ImportError:
    with open("/home/hoangtnk/Logs/collect_ip_vietnam.log", "a") as f:
        f.write(datetime.now().strftime("%d/%m/%Y %H:%M:%S") + ": Fatal error! IPaddress module has not been installed!\n")
    sys.exit()

    
def collect_ip():
   
    """ Collect public IP addresses """
   
    try:
        res = requests.get("https://www.vnnic.vn/vnix/danh-ba-ipasn")
    except Exception, exc:
        with open("/home/hoangtnk/Logs/collect_ip_vietnam.log", "a") as f:
            f.write(datetime.now().strftime("%d/%m/%Y %H:%M:%S") + ": %s\n" % str(exc))
    else:
        if res.status_code == 200:  # HTTP OK
            ipv4_list = re.findall(r"\d+.\d+.\d+.\d+/\d+", res.text)
            ipv6_list = [tup[0] for tup in re.findall(r"(([0-9a-fA-F]{1,4}:){2,4}:/\d+)", res.text)]
            for ip in ipv4_list:
                try:
                    ip_network(ip)
                except ValueError:
                    ipv4_list.remove(ip)
            for ipv6 in ipv6_list:
                try:
                    ip_network(ipv6)
                except ValueError:
                    ipv6_list.remove(ipv6)
            with open("/home/hoangtnk/PythonFiles/ip_vietnam.py", "w") as f:
            if len(ipv4_list) > 0:
                f.write("ipv4 = %s\n\n" % pformat(ipv4_list))
            if len(ipv6_list) > 0:
                f.write("ipv6 = %s" % pformat(ipv6_list))

                
if __name__ == "__main__":
    collect_ip()
