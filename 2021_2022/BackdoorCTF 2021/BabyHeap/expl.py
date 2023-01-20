#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./babyHeap')
host = args.HOST or '0.0.0.0'
port = int(args.PORT or 11451)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

def add()

libc=SetupLibcELF()
io = start()

R = Rootkit(io)
payload = R.Exploit()

io.interactive()
