#!/usr/bin/python3

import rootkit
from switchcase import switch

class XVM:
	def __init__(self, xvm_bytecodes):
		self.pc = 0
		self.eax = 0
		self.r1 = 0
		self.r2 = 0
		self.reg_id1 = 0
		self.reg_id2 = 0
		self.flag = 0
		self.zf = 0
		self.cf = 0
		self.rf = 0
		self.reg_array = {0 : "tmp", 1 : "r1", 2 : "r2", 7 : "flag"}
		self.regs = {"pc" : 0 , "eax" : 0, "r1" : 0, "r2" : 0, "tmp" : 0, "flag" : 0, "zf" : 0, "cf" : 0, "rf" : 1}
		self.opcode = 0
		self.instruction = rootkit.seperate(xvm_bytecodes, 4)

	def decode_ins(self, instruction):
		self.opcode  = int(instruction[3])
		self.reg_id2 = int(instruction[2])
		self.reg_id1 = int(instruction[1])

	def print_regs(self):
		print(f"pc			: {self.regs['pc']}")
		print(f"eax			: {self.regs['eax']}")
		print(f"reg_id1		: {self.reg_id1}")
		print(f"r1			: {self.regs['r1']}")
		print(f"reg_id2		: {self.reg_id2}")
		print(f"r2			: {self.regs['r2']}")
		print(f"flag		: {self.regs['flag']}")
		# print(f"zf			: {self.regs['zf']}")
		# print(f"cf			: {self.regs['cf']}")
		# print(f"rf			: {self.regs['rf']}")
		print(f"regs	    : {self.reg_array}")
		print(f"opcode		: {self.opcode}")


	def run_vm(self):
		for case in switch(self.opcode):
			if case(1):
				rootkit.warning(f"XOR {hex(rootkit.uu64(self.regs['r1']))} , {hex(rootkit.uu64(self.regs['r2']))}")
				self.regs["eax"] = rootkit.xor(self.regs["r1"] , self.regs["r2"])
				self.regs["r2"] = self.regs["eax"]
				break

			if case(2):
				self.regs["eax"] = self.reg_id1 & self.reg_id2
				break

			if case(3):
				self.regs["eax"] = self.reg_id1 | self.reg_id2
				break

			if case(4):
				if self.reg_id1:
					rootkit.warning(f"LOAD {self.reg_array[self.reg_id1]} , {hex(rootkit.uu64((self.instruction[self.regs['pc']+1])))}")
					self.regs[self.reg_array[self.reg_id1]] = self.instruction[self.regs["pc"]+1]
				else:
					rootkit.warning(f"LOAD {self.reg_array[self.reg_id2]} , {hex(rootkit.uu64((self.instruction[self.regs['pc']+1])))}")
					self.regs[self.reg_array[self.reg_id2]] = self.instruction[self.regs["pc"]+1]
				self.regs["pc"]+=1
				break

			if case(5):
				self.regs["r2"]=rootkit.uu64(self.regs["r2"])
				rootkit.warning(f"CMP {hex(self.regs['r2'])} , {hex(self.regs[self.reg_array[self.reg_id1]])}")
				if (self.regs["r2"] < self.regs[self.reg_array[self.reg_id1]]):
					self.zf=0
					self.cf=1
				if (self.regs["r2"] == self.regs[self.reg_array[self.reg_id1]]):
					self.zf=1
					self.cf=0
				break

			if case(6):
				rootkit.warning(f"STOP EXECUTION OF VM")
				self.regs["rf"]=0
				break

			if case(15):
				rootkit.warning(f"LOAD r1 , FLAG")
				self.regs["flag"] = inp
				break

		else:
			print("Seg Fault")
			exit(0)

	def start_vm(self):
		while self.regs["rf"]:
			ins=self.instruction[self.regs["pc"]]
			self.decode_ins(ins)
			self.run_vm()
			self.regs["pc"]+=1

inp = 0xf00dbab3
f=open("bytecode.xvm", "rb").read()
xvm_bytecodes=f[4:]
xvm=XVM(xvm_bytecodes)
xvm.start_vm()

"""
b'\x00\x00\x00\x0f'
b'\x00\x00\x01\x04' // opcode -> 4 ; r1 -> 1; r2 -> 0; 
b'\xd3\xda\\\m\x90'
b'\x00\x00\x02\x04'
b'AAAA'
b'\x00\x02\x01\x01'
b'\x00\x00\x01\x04'
b'!!!!'
b'\x00\x01\x00\x01'
b'\x00\x07\x00\x05'
b'\x00\x00\x00\x06'
"""