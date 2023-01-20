#!/usr/bin/python3
import numpy as np
from rootkit import *
io = remote("misc.challenge.bi0s.in", "1337")
lower_chars = "abcdefghijklmnopqrstuvwxyz"
# def create_array()

def remove_empty_items(str_list):
    str_list = list(filter(None, str_list))
    return str_list

def get_sym_coordinate1(arr2, ROW, COL):
    cords = {}
    for i in range(ROW):
        for j in range(COL):
            if arr2[i][j].strip(' ') in lower_chars:
                cords[arr2[i][j]] = [i, j]
    return cords

def get_sym_coordinate2(arr2):
    cords = {}
    for i in range(3):
        for j in range(3):
            for k in range(3):
                print(arr2[i, j, k])
                # if arr2[i][j][k].strip(' ') in lower_chars:
                    # cords[arr2[i][j][k]] = [i, j, k]
    return cords



def get_same_syms1(arr1, arr2, r, c):
    same = []
    for i in range(r):
        for j in range(c):
            # print(arr1[i][j], arr2[i][j])
            if arr1[i][j] == arr2[i][j]:
                same.append(i, j)
    return same

def get_same_syms2(arr1, arr2):
    same = []
    for i in 3:
        for j in 3:
            for k in 3:
                if arr1[i][j][k] == arr2[i][j][k]:
                    same.append(i, j, k)
    return same


def get_max_moves():
    reu("Max number of moves allowed: ")
    MAX_MOVES = int(rl().strip(b'\n'))
    return MAX_MOVES


def level1():
    ROW=2
    COL=2
    reu("Max number of moves allowed: ")
    MAX_MOVES = int(ren(1))
    rl()
    rl()
    data = reu("  \n+-------+  +-------+  \n").strip(b"  \n+-------+  +-------+  \n")
    data = data.decode('latin')
    data = data.split("  \n")
    tmp1 = data[0].split("  ")
    tmp2 = data[1].split("  ")
    tmp_arr1_row = remove_empty_items(tmp1[0].split("|"))
    tmp_arr2_row = remove_empty_items(tmp2[0].split("|"))
    tmp_arr1_col = remove_empty_items(tmp1[1].split("|"))
    tmp_arr2_col = remove_empty_items(tmp2[1].split("|"))
    arr1=tmp_arr1_row, tmp_arr2_row
    arr2=tmp_arr1_col, tmp_arr2_col
    kek1=np.array(arr1)
    kek2=np.array(arr2)
    same_xy_plots = get_same_syms1(arr1, arr2, ROW, COL)
    arr2_sym = get_sym_coordinate1(arr2, ROW, COL)
    arr1_sym = get_sym_coordinate1(arr1, ROW, COL)
    moves = []
    for syms in arr1_sym.keys():
        moves.append(arr1_sym[syms]+ arr2_sym[syms])

    for move in moves:
        move = str(move)[1:-1]
        sla("Enter move in the format 'current-x-cord,current-y-cord,to-x-cord,to-y-cord ' : ", str(move))

def level2():
    ROW, COL = 3, 3
    MAX_MOVES = get_max_moves()
    print(MAX_MOVES)
    data = reu("   \n+-----------+   +-----------+   \n").strip(b"   \n+-----------+   +-----------+   \n")
    data = data.decode('latin')
    print(data)
    data = remove_empty_items(data.split("  \n"))
    row1=remove_empty_items(data[0].split("   "))
    row2=remove_empty_items(data[1].split("   "))
    row3=remove_empty_items(data[2].split("   "))
    arr1_row1 = remove_empty_items(row1[0].split("|"))
    arr1_row1 = [x.strip(' ') for x in arr1_row1]
    arr2_row1 = remove_empty_items(row1[1].split("|"))
    arr2_row1 = [x.strip(' ') for x in arr2_row1]
    arr1_row2 = remove_empty_items(row2[0].split("|"))
    arr1_row2 = [x.strip(' ') for x in arr1_row2]
    arr2_row2 = remove_empty_items(row2[1].split("|"))
    arr2_row2 = [x.strip(' ') for x in arr2_row2]
    arr1_row3 = remove_empty_items(row3[0].split("|"))
    arr1_row3 = [x.strip(' ') for x in arr1_row3]
    arr2_row3 = remove_empty_items(row3[1].split("|"))
    arr2_row3 = [x.strip(' ') for x in arr2_row3]
    arr2_row1 = arr2_row1[:-1]
    arr2_row2 = arr2_row2[:-1]
    arr1=arr1_row1, arr1_row2, arr1_row3
    arr2=arr2_row1, arr2_row2, arr2_row3
    arr1=remove_empty_items(arr1)
    arr2=remove_empty_items(arr2)
    kek1=np.matrix(arr1)
    kek2=np.matrix(arr2)
    print(kek1)
    print(kek2)
    return kek1
    # a1 = get_sym_coordinate2(kek1)
    # print(a1)
    # print(arr2)
    # print(arr1)
    # arr2_sym = get_sym_coordinate2(arr2)
    # arr1_sym = get_sym_coordinate2(arr1)
    # print(arr1_sym)
    # print(arr2_sym)
    # kek1=np.array(arr1)
    # kek2=np.array(arr2)
    # same_xy_plots = get_same_syms1(arr1, arr2, ROW, COL)
    # moves = []


sla("Press 'y' to start: ", "y")
level1()
a=level2()

# io.interactive()