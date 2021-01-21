#!/usr/bin/python2.7
import angr
import claripy

proj = angr.Project('glee')
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"correct" in s.posix.dumps(1))
s = simgr.found[0]
print(s.posix.dumps(0))