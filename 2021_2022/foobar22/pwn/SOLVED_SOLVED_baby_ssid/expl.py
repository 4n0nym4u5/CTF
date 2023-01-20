#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./ssid')
host = args.HOST or 'chall.nitdgplug.org'
port = int(args.PORT or 30092)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()
sl(f"%s")
print(re())
io.interactive()
