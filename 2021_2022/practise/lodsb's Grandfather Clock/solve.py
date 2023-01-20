#!/usr/bin/python3

import qiling
from qiling import *
from qiling.const import QL_VERBOSE
import rootkit
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


def pp_idx(ql):
	print("A"*30)
	print("REG2 : " + str(hex(ql.reg.rax)))
	i = ql.stack_read(0x20)
	j = ql.stack_read(0x30)
	print(i, j)


ql = Qiling(["./grandfather_clock", "AA"], "/home/init0/qiling/examples/rootfs/x8664_linux", console=True, verbose=QL_VERBOSE.DEBUG)
# ql = Qiling(["./grandfather_clock", "AAAAAAAAAAAAAAAAAAAAAAAAAA"], "/home/init0/qiling/examples/rootfs/x8664_linux", console=False)
# ql.add_fs_mapper('./', './')
base_addr = ql.mem.get_lib_base(ql.path)

ql.hook_address(pp_idx, base_addr+0x000000000000145f)
ql.run()