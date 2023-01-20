#!/usr/bin/env python
def encrypt(string, shift):
 
  cipher = ''
  for char in string: 
    if char == ' ':
      cipher = cipher + char
    elif  char.isupper():
      cipher = cipher + chr((ord(char) + shift - 65) % 26 + 65)
    else:
      cipher = cipher + chr((ord(char) + shift - 97) % 26 + 97)
  
  return cipher

def solve(string, shift):
  return

text = input("enter string: ")
s = int(input("enter key: "))
print("original string: ", text)
print("after encryption: ", encrypt(text, s))

"""
The flag was encrypted using this script using the key 15. This is the output : bpztugttsdbaphiiwthidgb Reverse the encrption
and retrive the flag. Please make sure you are using python3 to run the script

FLAG FORMAT:
inctfj{...}
"""