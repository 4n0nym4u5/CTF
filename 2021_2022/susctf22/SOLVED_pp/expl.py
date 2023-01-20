#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./cat')
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 1234)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

R = Rootkit(io)
payload = R.Exploit()

io.interactive()
