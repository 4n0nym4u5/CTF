#!/usr/bin/env python3

from pwn import *

exe = ELF("./textsender")
libc = ELF("./libc-2.32.so")
ld = ELF("./ld-2.32.so")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([ld.path, exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
