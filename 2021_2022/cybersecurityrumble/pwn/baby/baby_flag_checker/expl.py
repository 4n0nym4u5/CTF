#!/usr/bin/env python3.9
# -*- coding: utf-8 -*-

from rootkit import *
import os
import time
import string
# Set up pwntools for the correct architecture
exe  = context.binary = ELF('chall')
host = args.HOST or 'challs.rumble.host'
port = int(args.PORT or 53921)

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

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

characters = string.printable[:-4]
# characters = "ABCD4"
known_flag=""
context.log_level='critical'
for oracle_byte in characters:
    io = start()
    try_flag = known_flag + oracle_byte 
    # try_flag=try_flag.ljust(128, "\n")
    sla(b"Enter the flag: ", try_flag)
    print(rl())
    # if b"Wrong flag" not in rl():
        # print(try_flag)
        # pause()
    # print(try_flag)
    io.close()

# io.interactive()
