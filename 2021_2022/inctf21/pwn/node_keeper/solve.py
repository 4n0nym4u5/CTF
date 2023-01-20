#!/usr/bin/env python3

from pwn import *

libc = ELF("./libc6_2.31-0ubuntu9.1_amd64.so")
ld = ELF("./ld-2.31.so")

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
