#!/usr/bin/env python3

from pwn import *

exe = ELF("./ld.so")
libc = ELF("./libc.so.6")

context.binary = exe


def conn():
    if args.LOCAL:
        return process([exe.path], env={"LD_PRELOAD": libc.path})
    else:
        return remote("addr", 1337)


def main():
    r = conn()

    # good luck pwning :)

    r.interactive()


if __name__ == "__main__":
    main()
