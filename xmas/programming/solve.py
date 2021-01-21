#!/usr/bin/python2.7
from pwn import *
import os
import sys
import numpy as np
"""
So you think you have what it takes to be a good programmer?
Then solve this super hardcore task:
Given an array print the first k1 smallest elements of the array in increasing order and then the first k2 elements of the array in decreasing order.
You have 50 tests that you'll gave to answer in maximum 30 seconds, GO!
Here's an example of the format in which a response should be provided:
1, 2, 3; 10, 9, 8
"""


io=remote("challs.xmas.htsp.ro" , "6051")
msg=io.recv().split("\n")

exec(msg[10])
exec(msg[9])
exec(msg[8])
# print(k1, k2, array)

my_array = np.asarray(array)
ascending = (np.sort(my_array)) #sort in ascending order
desc = (-np.sort(-my_array)) #sort in descending order 
print(k1, k2, array)
print(ascending[:k1])
inp =  ', '.join(map(str, ascending[:k1])) + "; " + ', '.join(map(str, desc[:k2]))
#b = ', '.join(map(str, ascending))
#c = ', '.join(map(str, desc))
#print("asc list = ", b, "\ndesc list = ", c)
print(inp)
print(desc[:k2])
io.sendline("1, 2, 3; 10, 9, 8")
print(io.recv())