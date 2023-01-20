#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from haxy import *

exe = context.binary = ELF('./gelcode-2')

host = args.HOST or 'mc.ax'
port = int(args.PORT or 31547)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path, "1000"] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path, "1000"] + argv, *a, **kw)

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
b *main+530
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()


shellcode = b""
shellcode += asm("syscall")
shellcode = shellcode.ljust(1000, "\x00")

io.interactive()

