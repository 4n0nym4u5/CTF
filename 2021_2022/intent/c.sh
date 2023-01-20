#!/bin/bash

nasm -f elf64 ape.asm
ld -s -o ape ape.o
