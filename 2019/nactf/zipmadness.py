#!/usr/bin/python2.7

import os
import sys
import zipfile

start_dir = "/home/init0/ctf/nactf/zipmadness/"
os.chdir("/home/init0/ctf/nactf/zipmadness/")

def get_direction():
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    for f in files:
        if f == "direction.txt":
            direction = open(f, "r").read()
            break
    return direction

def unzip_file(direction):
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    for f in files:
        if direction in f:
            with zipfile.ZipFile(f,"r") as zip_ref:
                zip_ref.extractall("junk")
while True:
    direction = get_direction()
    unzip_file(direction)
    print(direction)
    start_dir += "junk/"
    os.chdir(start_dir)

