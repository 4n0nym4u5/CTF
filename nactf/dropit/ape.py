#!/usr/bin/python3

from termcolor import colored
import sys
import os
import pwn
import argparse
import termcolor
import codecs

def unhex_invert(pattern , byte):
    pattern = args.offset.replace("0x", "")
    pattern = codecs.decode(pattern, 'hex')[::-1]
    pattern_offset = pwn.cyclic_find(pattern, n=byte)
    return pattern, pattern_offset

if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument("-l", "--length", type=int, default=512, help="cyclic length", action="store")
    parser.add_argument("-n", "--byte", type=int, default=8, help="cyclic byte", action="store")
    parser.add_argument("-o", "--offset", type=str, default="0xdeadbeef", help="find offset", action="store")
    parser.add_argument("-i", "--invert", default=False, help="Invert the offset", action="store_true")
    args = parser.parse_args()
    if args.offset == "0xdeadbeef":
        print("padding = '%s'" % colored(codecs.decode(pwn.cyclic(args.length, n=args.byte), 'utf-8'), 'magenta'))

    else:
        if args.invert:
            pattern, pattern_offset = unhex_invert(args.offset, args.byte)
            pattern = pattern[::-1]
            pattern_offset =  pwn.cyclic_find(pattern, n=args.byte)
            print("offset = {0} # pattern = {1}".format(str(colored(pattern_offset, 'cyan')) , str(colored(codecs.decode(pattern, 'utf-8'), 'cyan'))))
            print("padding = '{0}'".format(colored(codecs.decode(pwn.cyclic(pattern_offset, n=args.byte), 'utf-8'), 'magenta')))

        else:
            pattern, pattern_offset = unhex_invert(args.offset, args.byte)
            print("offset = {0} # pattern = {1}".format(str(colored(pattern_offset, 'cyan')) , str(colored(codecs.decode(pattern, 'utf-8'), 'cyan'))))
            print("padding = '{0}'".format(colored(codecs.decode(pwn.cyclic(pattern_offset, n=args.byte), 'utf-8'), 'magenta')))