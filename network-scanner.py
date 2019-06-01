#!/usr/bin/env python

import scapy.all as scapy


def scan(ip):
    arp_requets = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_requets_broadcast = broadcast/arp_requets
    answered_list = scapy.srp(arp_requets_broadcast,
                              timeout=1, verbose=False)[0]
    print("IP\t\t\tMAC Address\n--------------------------------------------------------------")
    for element in answered_list:
        print(element[1].psrc + "\t\t" + element[1].hwsrc)


scan("192.168.0.1/24")
