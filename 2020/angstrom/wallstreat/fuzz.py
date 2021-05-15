#!/usr/bin/python2
import gdb
junk_inp = '1\n-\n'
padding = "BBBBBBBB"

class PrintFrame(gdb.Command):
	"""Display the stack memory layout for the current frame"""

	def __init__ (self):
		super (PrintFrame, self).__init__ ("fuzz", gdb.COMMAND_STACK)

	def invoke(self, arg, from_tty):
		for i in range(0, 15):
			try:
				chain = padding + "%" + str(i) + "$n" + 'DDDDDDDD\n'
				f=open("inp", "w").write(chain)
				gdb.execute("run < inp")
				print("IDK")
				
				print("burd")

			except:
				print("FUCK ERRR")
				pass
PrintFrame()



