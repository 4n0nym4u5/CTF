#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep
from ctypes import CDLL
libc_ = CDLL("libc.so.6")


exe  = context.binary = ELF('./chall')
host = args.HOST or 'ctf.b01lers.com'
port = int(args.PORT or 9202)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()

def get_rand():

	s=""
	for i in range(4):
		s+=chr(libc_.rand() % 26 + 97)
	print(s)
	return s


io = start()

# R = Rootkit(io)
# payload = R.Exploit()
while True:
	reu(b"Your current balance: ")
	bal = int(rl().strip(b'\n'))
	sla(b'Guess me a string of length 4 with lowercase letters: ', get_rand() )
	if b"umen" in rl():
		rl()
		rl()
		print(rl())
		break

io.close()
