inp = AAAA
opcodes = [9, 36, 42, 44, 16, 9, 21, 24, 44, 20, 40, 9, 10, 43, 44, 44, 9, 10, 43, 44, 44, 9, 10, 43, 44, 44, 9, 10, 43, 44, 44, 9, 10, 43, 36, 39, 9, 24, 23, 41]

struct hell86_vm{
	short ud2_ins
}

```
0 : 0xf
1 : 0xb
2 : 0x2
3 : 0x0
4 : 0x0
5 : 0x0
6 : 0x0
7 : 0x0
8 : 0x0
9 : 0x0
10 : 0x9
11 : 0xd
12 : 0x0
13 : 0x0
```


.text:0000000000001238                 db 0                    ; field_D
.text:0000000000001246                 db  0Fh
.text:0000000000001247                 db  0Bh
.text:0000000000001248                 dq offset aFlag         ; "FLAG{"
.text:0000000000001250                 db 9, 8, 2 dup(0), 0Fh, 0Bh
.text:0000000000001256                 dq offset loc_17DA
.text:000000000000125E                 dw 28h



first vm case
0x9 -> 
next_ud2 is set to 0xd

