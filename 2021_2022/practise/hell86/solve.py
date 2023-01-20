#!/usr/bin/python3


def get_opcodes():
    gdb_cmd("r AAAA")
    gdb_cmd("brva 0x1eeb")
    i=1
    opcodes=[]
    gdb_cmd("c")
    opcodes.append(9)
    while True:
        gdb_cmd("c")
        gdb_cmd("c")
        gdb_cmd("p/d $rdx")
        reu(f"${i} = ".encode("latin-1"), timeout=3)
        try:
            opcode=int(rl().strip(b"\n"))
        except:
            return opcodes
        opcodes.append(opcode)
        # print(opcodes)
        i+=1
        re()

def get_vm_bytes():
    gdb_cmd("r AAAA")
    return exe.read(exe.address+0x1190, 0x1946-0x1190)





from rootkit import *
from time import sleep
exe=ELF("./hell86")
exe.address=0x555555400000
io=auto_gdb(pwndbg=True)
gdb_cmd("file hell86")
# pp=get_opcodes()
vm_bytes=get_vm_bytes()
for i in range(0x20):
    print(hex(vm_bytes[i]))
io.interactive()