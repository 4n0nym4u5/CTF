#!/bin/sh
gcc -o exploit -static exploit.c
sudo mv ./exploit fs
sudo genext2fs -b 16384 -d fs abcd.ext2
sudo chown -R init0:init0 abcd.ext2