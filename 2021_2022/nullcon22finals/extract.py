#!/usr/bin/env python3
a = 1
pp = ""
with open("a.txt", "r") as file:
    for line in file.readlines():
        print(line)
        if a % 2 != 0:
            tmp = line.split("=")[1]
        if a % 2 == 0:
            tmpp = line.split("==")
            tmpp[0] = tmp
            pp += "==".join(tmpp)

        a = a + 1
print(pp)
