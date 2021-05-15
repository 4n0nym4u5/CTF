#!/usr/bin/python2
# -*- coding: utf-8 -*-

from pwn import *
reu = lambda a : io.recvuntil(a)
sla = lambda a,b : io.sendlineafter(a,b)
sl = lambda a : io.sendline(a)
rel = lambda : io.recvline()
sa = lambda a,b : io.sendafter(a,b)
re = lambda a : io.recv()
s = lambda a : io.send(a)

def gen_symbols(a1):
    reu("{a1} -> ".format(a1=a1))
    tmp = int(reu(" ").strip(b" "))
    log.info("{a1} -> {tmp}".format(a1=a1, tmp=tmp))
    return tmp

def calc():
    reu(":\n\n")
    expr = reu(" = ?").strip(" = ?")
    log.info("Equation : {expr}".format(expr=expr))
    expr = expr.replace("🌞", str(sun))
    expr = expr.replace("🍨", str(rice))
    expr = expr.replace("❌", str(cross))
    expr = expr.replace("🍪", str(cookie))
    expr = expr.replace("🔥", str(fire))
    expr = expr.replace("⛔", str(dnd))
    expr = expr.replace("🍧", str(icecream))
    expr = expr.replace("👺", str(bitch))
    expr = expr.replace("👾", str(alien))
    expr = expr.replace("🦄", str(horse))
    log.info("Equation fucked : {expr}".format(expr=expr))
    answer = eval(expr)
    io.sendlineafter("Answer: ", str(answer))
    print(io.recvline())
    print(io.recvline())
    print(io.recvline())
    log.info("LEVEL : {i}".format(i=i))


io = remote("138.68.168.137", "31184")
sla("> ", "1")
reu("Here is a little help:\n\n")
sun = gen_symbols("🌞")
rice = gen_symbols("🍨")
cross = gen_symbols("❌")
cookie = gen_symbols("🍪")
fire = gen_symbols("🔥")
dnd = gen_symbols("⛔")
icecream = gen_symbols("🍧")
bitch = gen_symbols("👺")
alien = gen_symbols("👾")
horse = gen_symbols("🦄")
sla("> ", "2")
for i in range(500):
    calc()
io.interactive()

