#!/usr/bin/env python3

from pwn import remote, process
import time
import ctypes
import random
from datetime import datetime
import sys

server = sys.argv[1]
port = int(sys.argv[2])
r = remote(server, port)
# r = process('./a.out')
s = r.recvuntil(">")
r.recvuntil(": ")
s = s.decode().split(" >")[0]
print(s)

dt = datetime.now()
ymd = dt.strftime("%Y-%m-%d %H:%M:%S").split(" ")[0]
print(ymd)
timestamp = time.mktime(time.strptime(ymd + " " + s, "%Y-%m-%d %H:%M:%S"))
# print(timestamp)

libc = ctypes.CDLL("libc.so.6")  
libc.srand(int(timestamp))
pwd = libc.rand()

print(pwd)
r.sendline(str(pwd))
print(r.recvall(1).decode())