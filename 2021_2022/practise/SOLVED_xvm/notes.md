### hint : this vm has no jmp instruction

### run_vm

```c

__int64 __fastcall run_vm(__int64 xvm, unsigned int bytecodes)
{
  unsigned int reg2_; // [rsp+14h] [rbp-2Ch]
  unsigned int reg1_; // [rsp+18h] [rbp-28h]
  char flags[4]; // [rsp+20h] [rbp-20h] BYREF
  int opcode; // [rsp+24h] [rbp-1Ch]
  int reg2; // [rsp+28h] [rbp-18h]
  int reg1; // [rsp+2Ch] [rbp-14h]
  unsigned __int64 v9; // [rsp+38h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  get_regs_ig(flags, bytecodes);
  reg2_ = reg2;
  reg1_ = reg1;
  switch ( opcode )
  {
    case 1:
      *(xvm + 4) = **(xvm + 8 * (reg1 + 4LL) + 8) ^ **(xvm + 8 * (reg2 + 4LL) + 8);// [reg1] ^ [reg2]
      return 0LL;
    case 2:
      *(xvm + 4) = (reg1 & reg2);
      return 0LL;
    case 3:
      *(xvm + 4) = reg1 | reg2;
      return 0LL;
    case 4:
      **(xvm + 8 * (reg2_ + 4LL) + 8) = idk[++*xvm];
      return 0LL;
    case 5:                                     // check_flag ig
      if ( **(xvm + 8 * (reg2 + 4LL) + 8) < **(xvm + 8 * (reg1 + 4LL) + 8) )
      {
        *(xvm + 120) = 0;                       // wrong flag
        *(xvm + 121) = 1;
      }
      if ( **(xvm + 8 * (reg2_ + 4LL) + 8) == **(xvm + 8 * (reg1_ + 4LL) + 8) )
      {
        *(xvm + 120) = 1;                       // correct flag
        *(xvm + 121) = 0;
      }
      return 0LL;
    case 6:
      *(xvm + 122) = 0;
      return *(xvm + 120);                      // stop the execution of vm
    case 0xF:
      *(xvm + 32) = flag;
      return 0LL;
    default:
      return 0LL;
  }
}

```


### solution

0xf : load our input flag to memory
0x4 : load 0x906DDAD3 to memory
0x4 : load 0x41414141 to memory
0x1 : xor 0x41414141 ^ 0x906DDAD3 => `0xd12c9b92` stored at `*(xvm + 4)`
0x4 : load 0x21212121 to memory
0x1 : xor 0x21212121 ^ 0xd12c9b92 `*(xvm + 4)` => `0xf00dbab3` stored at `*(xvm + 4)`
0x5 : compare our input to 0xf00dbab3
0x6 : set RUN_VM_FLAG `*(start_of_struct + 122)` to false. Stop the execution of the vm

free the allocated memory for xvm

```
[!] flag decrypted
FLAG : FLAG{-267535693}

```