#!/usr/bin/env python

import scapy.all as scapy
import optparse


def handler_user_input():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="ip", help="Target IP/IP range to scan")
    (options, arguments) = parser.parse_args()
    if not options.ip:
        parser.error("[-] Please use -t or --target before specifying an IP range, use -- help for more info")

    return options.ip


def scan(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []

    for item in answered_list:
        client_dict = {"IP": item[1].psrc, "MAC Address": item[1].hwsrc}
        clients_list.append(client_dict)

    return clients_list


def print_result(results_list):
    print("\n")
    print("IP\t\tMAC Address")

    for item in results_list:
        print(item["IP"] + "\t" + item["MAC Address"])
        print("----------------------------------------")


ip = handler_user_input()
results_list = scan(ip)
print_result(results_list)
