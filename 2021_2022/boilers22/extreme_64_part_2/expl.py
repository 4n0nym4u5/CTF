#!/usr/bin/python3

import pwn
from rootkit import rl, sl, reu, sla, re

io = pwn.remote('ctf.b01lers.com', '9302')


def send_password(password):
	sla(b'>>> ', password)

def send_cmd_get_flag(cmd):
	send_cmd(cmd)
	a=get_flag()
	return a

def send_cmd(cmd):
	sla(b'>>> ', cmd)

def get_flag():
	reu(b"Level password is: ")
	return rl().strip(b'\n')


# level 1
send_password('')
flag=send_cmd_get_flag('add rdi, rsi;\nmov rax, rdi\n')
print(flag)

# sla(b'>>> ', '')
# sla(b'>>> ', 'add rdi, rsi;\nmov rax, rdi\n')
# reu(b"Level password is: ")
# password = rl().strip(b'\n')

# level 2
send_password(flag)


io.interactive()