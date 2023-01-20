#!/usr/bin/python3
from rootkit import *
import hexdump


io = remote("auto-pwn.chal.csaw.io", "11001")
re()
sl("cd80d3cd8a479a18bbc9652f3631c61c")
rl()
rl()
hex_dump_data = reu("            ............").strip(b"            ............")
hex_dump_data = hex_dump_data + b"            ............"
print(hex_dump_data)
kek=hexdump.restore(hex_dump_data)
# print(kek)
io.close()