#!/usr/bin/env python
#
# DNS sniffing using scapy module
from __future__ import print_function

import sys
sys.path.append("/home/hoangtnk/PythonFiles")

try:
    from ipaddress import ip_address, ip_network
    from colorama import init, deinit, Fore, Style
    import ip_vietnam
except ImportError:
    presence = False  # check if we should color-print Vietnam' IPs
else:
    presence = True

import argparse
import logging
import socket
import re

try:
    from scapy.all import *
except ImportError:
    print("Scapy module has not been installed on this system.")
    print("Download it from https://pypi.python.org/pypi/scapy and try again.")
    sys.exit()


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.interactive").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)


def name_to_ip(pkt):
   
    """ Find name to IP mapping """
   
    if pkt.haslayer(DNS):
        i = 0
        if args.n is not None:
            for name in args.n:
                try:
                    if re.search(r"%s" % name, pkt[DNS].qd.qname) is not None:
                        if presence:
                            while True:
                                if (pkt[DNS].an[i].type == 1):  # type A (IPv4 address)
                                    for ip in ip_vietnam.ipv4:
                                        if ip_address(unicode(pkt[DNS].an[i].rdata)) in ip_network(ip):
                                            return Style.RESET_ALL + Fore.RESET + "%s <-> " % pkt[DNS].qd.qname + Style.BRIGHT + Fore.GREEN + "%s " % pkt[DNS].an[i].rdata + Style.RESET_ALL + Fore.RESET + "(TTL=%d, queried by %s)" % (pkt[DNS].an[i].ttl, pkt[IP].dst)
                                    return Style.RESET_ALL + Fore.RESET + "%s <-> %s (TTL=%d, queried by %s)" % (pkt[DNS].qd.qname, pkt[DNS].an[i].rdata, pkt[DNS].an[i].ttl, pkt[IP].dst)
                               
                                elif (pkt[DNS].an[i].type == 28):  # type AAAA (IPv6 address)
                                    for ipv6 in ip_vietnam.ipv6:
                                        if ip_address(unicode(pkt[DNS].an[i].rdata)) in ip_network(ipv6):
                                            return Style.RESET_ALL + Fore.RESET + "%s <-> " % pkt[DNS].qd.qname + Style.BRIGHT + Fore.GREEN + "%s " % pkt[DNS].an[i].rdata + Style.RESET_ALL + Fore.RESET + "(TTL=%d, queried by %s)" % (pkt[DNS].an[i].ttl, pkt[IP].dst)
                                    return Style.RESET_ALL + Fore.RESET + "%s <-> %s (TTL=%d, queried by %s)" % (pkt[DNS].qd.qname, pkt[DNS].an[i].rdata, pkt[DNS].an[i].ttl, pkt[IP].dst)
                               
                                else:  # type 5 (cname)
                                    i += 1
                        else:
                            while True:
                                if (pkt[DNS].an[i].type == 1) or (pkt[DNS].an[i].type == 28):
                                    return Style.RESET_ALL + Fore.RESET + "%s <-> %s (TTL=%d, queried by %s)" % (pkt[DNS].qd.qname, pkt[DNS].an[i].rdata, pkt[DNS].an[i].ttl, pkt[IP].dst)
                                else:
                                    i += 1
                except TypeError:
                    pass
                except AttributeError:
                    pass
                except IndexError:
                    pass
        else:
            try:
                if presence:
                    while True:
                        if (pkt[DNS].an[i].type == 1):
                            for ip in ip_vietnam.ipv4:
                                if ip_address(unicode(pkt[DNS].an[i].rdata)) in ip_network(ip):
                                    return Style.RESET_ALL + Fore.RESET + "%s <-> " % pkt[DNS].qd.qname + Style.BRIGHT + Fore.GREEN + "%s " % pkt[DNS].an[i].rdata + Style.RESET_ALL + Fore.RESET + "(TTL=%d, queried by %s)" % (pkt[DNS].an[i].ttl, pkt[IP].dst)
                            return Style.RESET_ALL + Fore.RESET + "%s <-> %s (TTL=%d, queried by %s)" % (pkt[DNS].qd.qname, pkt[DNS].an[i].rdata, pkt[DNS].an[i].ttl, pkt[IP].dst)
                               
                        elif (pkt[DNS].an[i].type == 28): 
                            for ipv6 in ip_vietnam.ipv6:
                                if ip_address(unicode(pkt[DNS].an[i].rdata)) in ip_network(ipv6):
                                    return Style.RESET_ALL + Fore.RESET + "%s <-> " % pkt[DNS].qd.qname + Style.BRIGHT + Fore.GREEN + "%s " % pkt[DNS].an[i].rdata + Style.RESET_ALL + Fore.RESET + "(TTL=%d, queried by %s)" % (pkt[DNS].an[i].ttl, pkt[IP].dst)
                            return Style.RESET_ALL + Fore.RESET + "%s <-> %s (TTL=%d, queried by %s)" % (pkt[DNS].qd.qname, pkt[DNS].an[i].rdata, pkt[DNS].an[i].ttl, pkt[IP].dst)
                               
                        else: 
                            i += 1
                else:
                    while True:
                        if (pkt[DNS].an[i].type == 1) or (pkt[DNS].an[i].type == 28):
                            return Style.RESET_ALL + Fore.RESET + "%s <-> %s (TTL=%d, queried by %s)" % (pkt[DNS].qd.qname, pkt[DNS].an[i].rdata, pkt[DNS].an[i].ttl, pkt[IP].dst)
                        else:
                            i += 1
            except TypeError:
                pass
            except AttributeError:
                pass
            except IndexError:
                pass


def main():
   
    """ Main function """
   
    global args
    global presence
   
    parser = argparse.ArgumentParser(description="DNS sniffing to quickly find name to IP mapping")
    parser.add_argument("-n", metavar="name", nargs="+", help="domain name to find name <-> IP (default all)")
    parser.add_argument("-s", metavar="src", nargs="+", help="host from which to sniff DNS packets (default all)")
    parser.add_argument("-i", metavar="iface", help="interface on which to sniff DNS packets (default all)")
    parser.add_argument("-c", metavar="count", type=int, default=0, help="number of DNS packets to sniff (default infinity)")
    parser.add_argument("-g", default=False, action="store_const", const=True, help="color-print Vietnam' IPs (default not set)")
    args = parser.parse_args()
    if args.g:
        if not presence:
            print("Cannot color-print Vietnam' IPs due to some of these reasons:")
            print("  + IPaddress module has not been installed")
            print("  + Colorama module has not been installed")
            print("  + Vietnam's IP database is not available (run collect_ip_vietnam.py to populate it)\n")
        else:
            init()
    else:
        presence = False
    print("Sniffing DNS packets...")
    try:
        if args.s is not None:
            sniff(filter="dst host (%s) and src port 53" % (" or ".join(args.s)), iface=args.i, count=args.c, prn=name_to_ip, store=0)  # only sniff DNS answers
        else:
            sniff(filter="src port 53", iface=args.i, count=args.c, prn=name_to_ip, store=0) 
    except socket.error:
        print("Wrong interface and/or not run as superuser.")
        if presence:
            deinit()
        sys.exit()
    except Scapy_Exception:
        print("Syntax error.")
        if presence:
            deinit()
        sys.exit()
    except KeyboardInterrupt:
        if presence:
            deinit()
        sys.exit()


if __name__ == "__main__":
    main()
