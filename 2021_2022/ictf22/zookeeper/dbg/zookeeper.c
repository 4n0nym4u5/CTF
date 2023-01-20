int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int *length; // rbx
  char input; // [rsp+3h] [rbp-1Dh] BYREF
  int finding_lion_idx; // [rsp+4h] [rbp-1Ch] MAPDST BYREF
  unsigned __int64 v7; // [rsp+8h] [rbp-18h]

  v7 = __readfsqword(0x28u);
  puts("Are you fit to be the keeper of the zoo?");
  while ( 1 )
  {
    do
    {
      while ( 1 )
      {
        while ( 1 )
        {
          puts("(f)ind a lion");
          puts("(l)ose a lion");
          puts("(v)iew a lion");
          __isoc99_scanf("%c%*c", &input);
          if ( input != 'f' )
            break;

            //# Gets the index
          puts("idx:");
          __isoc99_scanf("%d%*c", &finding_lion_idx);

            //# Checks if idx goes out of bound
          if ( finding_lion_idx < 0 || finding_lion_idx > 16 )
            exit(0);
            
            //# each lion holder has a size of 0x50
          *((_QWORD *)&mem + finding_lion_idx) = malloc(0x50uLL);
          puts("len:");

            //# len at the front
            //# lion + 0x0 == length
          __isoc99_scanf("%d%*c", *((_QWORD *)&mem + finding_lion_idx));

            //lion position
          length = (int *)*((_QWORD *)&mem + finding_lion_idx);

          //# lion + 0x8 = heap pointer
          *((_QWORD *)length + 1) = malloc(*length);
            
            //lion + 0x10 = valid management
          strcpy((char *)(*((_QWORD *)&mem + finding_lion_idx) + 16LL), "valid management");
          
          puts("content:");
            
            //read into that heap chunk
          read(0, *(void **)(*((_QWORD *)&mem + finding_lion_idx) + 8LL), **((int **)&mem + finding_lion_idx));

            //null terminate it
          *(_BYTE *)(*(_QWORD *)(*((_QWORD *)&mem + finding_lion_idx) + 8LL) + **((int **)&mem + finding_lion_idx) - 1LL) = 0;
        }

        // # Losing lion . free
        if ( input != 'l' )
          break;
        puts("idx:");
        __isoc99_scanf("%d%*c", &finding_lion_idx);

        if ( finding_lion_idx < 0 || finding_lion_idx > 16 )
          exit(0);

        if ( strncmp((const char *)(*((_QWORD *)&mem + finding_lion_idx) + 16LL), "valid management", 0x10uLL) )
          exit(0);

        free(*((void **)&mem + finding_lion_idx));
        free(*(void **)(*((_QWORD *)&mem + finding_lion_idx) + 8LL));
        *((_QWORD *)&mem + finding_lion_idx) = 0LL;// erase the entry on the global notepad (mem)
      }
    }
    while ( input != 'v' );
    puts("idx:");
    __isoc99_scanf("%d%*c", &finding_lion_idx);
    if ( finding_lion_idx < 0 || finding_lion_idx > 16 )
      exit(0);
    if ( strncmp((const char *)(*((_QWORD *)&mem + finding_lion_idx) + 16LL), "valid management", 0x10uLL) )
      exit(0);
    puts(*(const char **)(*((_QWORD *)&mem + finding_lion_idx) + 8LL));
  }
}

/*
2 lion can have the same pointer

- probably some overlapping chunk?

*/