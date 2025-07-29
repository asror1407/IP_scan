# IP_scan
IP manzillarni skaner qiluvchi dastur (Python, scapy)

import argparse
import scapy.all as scapy

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", dest="ip_range", help="Scaner qilish uchun IP manzil kiriting")
    args = parser.parse_args()

    if not args.ip_range:
        parser.error("[-] Iltimos IP manzil kiriting. -h/--help ko'proq ma'lumot olish uchun")

    return args

def scanner(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, iface="eth1", verbose=False)[0]

    print("IP\t\t\tMAC address\n-----------------------------------------")
    client_list = []
    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "MAC address": element[1].hwsrc}
        client_list.append(client_dict)
        print(f"{element[1].psrc}\t\t{element[1].hwsrc}")
    
    return client_list


args = get_arguments() scanner(args.ip_range)
