#include <stdio.h>
#include <stdlib.h>
#include <string.h>


char *enc(const char *a1)
{
  void *v1; // rax
  char v3; // [rsp+1Fh] [rbp-31h]
  size_t i; // [rsp+20h] [rbp-30h]
  size_t inp_len_min_1; // [rsp+28h] [rbp-28h]
  size_t len_of_inp; // [rsp+30h] [rbp-20h]
  char *v7; // [rsp+38h] [rbp-18h]

  len_of_inp = strlen(a1);
  i = 0LL;
  inp_len_min_1 = len_of_inp - 1;
  v3 = -2;
  v1 = malloc(len_of_inp + 1);
  v7 = memset(v1, 0, len_of_inp + 1);
  while ( i < len_of_inp )
  {

    v7[i] = a1[inp_len_min_1] - 32;
    printf("%c\n", v7[i]);
    inp_len_min_1 += v3;
    if ( inp_len_min_1 == -1LL )
    {
      printf("in %ld\n", inp_len_min_1);
      inp_len_min_1 = 0LL;
      v3 = -v3;
    }
    printf("out %ld\n", inp_len_min_1);

    ++i;
  }
  return v7;
}

int main(int argc, char const *argv[])
{
	puts(enc("AAAA"));
	return 0;
}