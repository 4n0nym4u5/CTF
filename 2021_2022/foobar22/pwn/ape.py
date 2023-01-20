#!/usr/bin/python3

import pwn

import string

whitelisted=[]
blacklisted=[]
for i in string.printable:
	io=pwn.remote("chall.nitdgplug.org", "30622")
	io.recv()
	io.sendline(str(i))
	if b"Executing..." in io.recv():
		whitelisted.append(str(i))
	else:
		blacklisted.append(str(i))
	io.close()
print(whitelisted)
print(blacklisted)