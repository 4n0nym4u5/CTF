#!/usr/bin/python2
import gdb


class FillPattern(gdb.Command):
    """Display the stack memory layout for the current frame"""

    def __init__(self):
        super(FillPattern, self).__init__("pattern_fill", gdb.COMMAND_STACK)

    def invoke(self, arg, from_tty):
        a = 0xDEADB000
        for i in range(0x7FFFF7FC1000, 0x7FFFF7FC3000, 8):
            try:
                a = a + 1
                gdb.execute(f"set *{i}={a}")
            except:
                print("FUCK ERRR")
                pass


FillPattern()
