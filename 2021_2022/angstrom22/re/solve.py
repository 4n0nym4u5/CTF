#!/usr/bin/python3

from rootkit import *
from time import sleep
import string

known_bytes = "NT4{ftcD1R0wor}FlAnm"
no_of_hits = len(known_bytes)

def pass_it():
	sleep(0.2)
	sl("continue")
	sleep(0.2)

dude = "NfTRcD1ontrw}4{mFl_Ad0ua"
"""
while len(known_bytes) != len(dude):
	for i in dude:
		if i in known_bytes:
			continue
		io = auto_gdb()
		
		gdb_cmd("file ./flatland")
		
		gdb_cmd("b *getc")
		gdb_cmd("run")
		sleep(0.2)
		gdb_cmd("continue")
		sleep(0.2)
		
		inp = known_bytes + i
		
		re()
		sleep(0.2)
		sl(inp)
		sleep(0.2)
		if b"Breakpoint" in re():
			for j in range(len(known_bytes)):
				pass_it()
			if b"All the substantial binaries" not in re():
				known_bytes += i
				info(f"flag := {known_bytes}")
				break
		io.close()

"""
known_bytes = "actf{"
for i in dude:
	io = auto_gdb()

	gdb_cmd("file ./flatland")
	# gdb_cmd("b *0x0000000000401240")
	gdb_cmd("b *0x0000000000401234")
	gdb_cmd("run")
	sleep(0.2)
	inp = known_bytes + i
	print(inp)
	sa(" who are privileged to have control flow.\n", inp)
	sleep(0.2)
	gdb_cmd("p/x $rax")
	print(rl().decode("utf-8"), i)
	# gdb_cmd("info registers")
	# for i in range(16):
		# print(rl())
	io.close()


# actfrowduT4{F}D1R0l
#     [+] flag := NT4{ftcD1R0wor}Fl
# NT4{ftcD1R0wor}FlAnm

# on
# 0x0000000000401240 win check eax shud be 6