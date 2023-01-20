#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

from rootkit import *
import os
import time

# Set up pwntools for the correct architecture
exe  = context.binary = ELF('./echo-echo')
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

io = start()

R = Rootkit()
payload = R.Exploit()

io.interactive()
