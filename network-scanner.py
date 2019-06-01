#!/usr/bin/env python3

import scapy.all as scapy
import argparser


def getArguments():
    parser = argparser.ArgumentParser()
    parser.add_argument("-t", "--target", dest=target,
                        help="Target IP / IP range.")
    options = parser.parse_args()
    return options


def scan(ip):
    arp_requets = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_requets_broadcast = broadcast/arp_requets
    answered_list = scapy.srp(arp_requets_broadcast,
                              timeout=1, verbose=False)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
        print(element[1].psrc + "\t\t" + element[1].hwsrc)
    return clients_list


def print_relsult(result_list):
    print("IP\t\t\tMAC Address\n--------------------------------------------------------------")
    for client in result_list:
        print(client["ip" + "\t\t" + client["mac"]])


options = get_arguments()
scan_result = scan(options.target)
print_relsult(scan_result)
