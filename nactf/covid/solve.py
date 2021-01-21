#!/usr/bin/env python3

from pwn import *

exe = ELF("chall")
libc = ELF("./libc.so.6")
ld = ELF("ld.so.2")

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
