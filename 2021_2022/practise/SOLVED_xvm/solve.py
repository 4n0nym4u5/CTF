#!/usr/bin/python3

from qiling import *
from qiling.const import QL_VERBOSE
from rootkit import *
import sys

sys.path.append("..")

class StringBuffer:
    def __init__(self):
        self.buffer = b''

    def read(self, n):
        ret = self.buffer[:n]
        self.buffer = self.buffer[n:]
        return ret

    def readline(self, end=b'\n'):
        ret = b''
        while True:
            c = self.read(1)
            ret += c
            if c == end:
                break
        return ret

    def write(self, string):
        self.buffer += string
        return len(string)


def print_opcode(ql):
	warning("OPCODE : " + str(hex(ql.reg.rax)))

def print_reg1(ql):
	warning("REG1 : " + str(hex(ql.reg.rax)))

def print_reg2(ql):
	warning("REG2 : " + str(hex(ql.reg.rax)))

def XOR_(ql):
	warning(f"XOR {WHITE(hex(ql.reg.edx))} {WHITE(hex(ql.reg.eax))}")

def MOVE_(ql):
	warning(f"MOVE {CYAN(hex(ql.reg.rax))} {WHITE(hex(ql.reg.edx))} ")

def LOAD_INPUT(ql):
	warning(f"LOAD {CYAN(hex(ql.reg.rax+0x20))} {WHITE(hex(ql.reg.edx))} ")

def CMP_FLAG(ql):
	if hex(ql.reg.edx) < hex(ql.reg.eax):
		result = f"{GREEN('True')}"
	else:
		result = f"{RED('False')}"
	
	warning(f"CMP {WHITE(hex(ql.reg.edx))} < {WHITE(hex(ql.reg.eax))} {result}")

	if hex(ql.reg.edx) == hex(ql.reg.eax):
		result = f"{GREEN('True')}"
	else:
		result = f"{RED('False')}"
	
	warning(f"CMP {WHITE(hex(ql.reg.edx))} == {WHITE(hex(ql.reg.eax))} {result}")
	
	if ql.reg.edx == ql.reg.eax:
		info(f"FLAG {GREEN(hex(ql.reg.eax))}")

def STOP_VM(ql):
	warning("STOPPING VM EXECUTION")
	exit(0)


ql = Qiling(["vm", "bytecode.xvm"], "/home/init0/qiling/examples/rootfs/x8664_linux", console=False)
ql.add_fs_mapper('./', './')
ql.os.stdin = StringBuffer()
ql.os.stdin.write(b"4027431603\n")
base_addr = ql.mem.get_lib_base(ql.path)
# ql.hook_address(print_opcode, base_addr+0x0ee8)
# ql.hook_address(print_reg1, base_addr+0x0ec2)
# ql.hook_address(print_reg2, base_addr+0x0ed8)
ql.hook_address(XOR_, base_addr+0xf42)
ql.hook_address(MOVE_, base_addr+0xfb1)
ql.hook_address(LOAD_INPUT, base_addr+0xf16)
ql.hook_address(CMP_FLAG, base_addr+0xfdc)
ql.hook_address(STOP_VM, base_addr+0x103a)

ql.run()
