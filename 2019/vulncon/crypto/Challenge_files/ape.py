#!/usr/bin/env python2
from PIL import Image,ImageDraw,ImageFont
from pwn import xor
from os import urandom
from itertools import cycle

def divideString(string, n): 
    str_size = len(string) 
  
    # Check if string can be divided in n equal parts 
    if str_size % n != 0: 
        print "Invalid Input: String size is not divisible by n"
        return
  
    # Calculate the size of parts to find the division points 
    part_size = str_size/n 
    k = 0
    for i in string: 
        if k%part_size==0: 
            print "\n", 
        print i, 
        k += 1

flag = "inctfj{XOR_i5_4_RE4LLY_5UPRi5iNG_0P3R4TOr}"
def XOR(data,key):
    return ''.join(chr(ord(i)^ord(j)) for i,j in zip(data,cycle(key)))

def make_file(text):
    image = Image. new('RGB', (585,45), color = (255,255,255))
    fnt = ImageFont.truetype('Chalkduster.ttf',20)
    txt = ImageDraw.Draw(image)
    txt. text((10,10), flag, font=fnt, fill=(0,0,0))
    name = 'test.png'
    image.save(name)
    return name

def get_key(i):
    ct  = open('smokeaway.jpg.enc', 'r').read()
    ct  = ct[:int(i)]
    pt  = open('4pnwam-1.jpg', 'r').read()
    pt  = pt[:int(i)]
    print(pt)
    print(ct)
    key = xor(ct, pt).encode('hex')
    return key

def encrypt(file_name, key):
   # global i
   file = open(file_name,'rb')
   content = file.read()
   file.close()
   # key =  "2f7866662f786438"
   # key = get_key()
   print(len(key))
   key = key.decode("hex")
   print((key))
   print(key.encode('hex'))

   enc_data = xor(content,key)
   file_pp = "lund.jpg"
   new_file = open(file_pp,'w')
   new_file.write(enc_data)
   new_file.close()

def main():
    global i
    for i in range(20):
    #get_key()
    #flag_file = make_file(flag)
        # global i
        key = get_key(i)
        encrypted_file = encrypt("smokeaway.jpg.enc", key)
        print('your file is succesfully saved in {} file!'.format(encrypted_file))
        # return encrypted_file

if __name__ == '__main__':
    encrypt("smokeaway.jpg.enc", "46ccf9a571f0ffb17e41cb8446cdf88870ddffb17e7bea")

"""
00000020: f70e 4559 d0ad 4441 5822 13e3 3608 00d8  ..EY..DAX"..6...

00000020: f70e 4559 d0ad 3d41 5822 13e3 3608 00d8  ..EY..=AX"..6...

00000020: f70e 4559 d0ad 447f 5822 13e3 3608 00d8  ..EY..D.X"..6...

00000020: f70e 4559 d054 4441 5822 13e3 3608 00d8  ..EY.TDAX"..6...
00000020: f70e 4559 d054 4441 5822 13e3 3608 00d8  ..EY.TDAX"..6...
00000020: f70e 4559 d0ad 4441 5822 13e3 3608 00d8  ..EY..DAX"..6...

\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xdb\x00
\xb9\x14\x06\x45\x71\xe0\xb5\xf7\x37\x07\xcb\x85\x47\xcd\xf8\x89\x70\xdc\xff\xb1\x81\xa0\xea
"""