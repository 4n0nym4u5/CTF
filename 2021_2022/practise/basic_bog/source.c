#include <stdio.h>
#include <stdlib.h>

int main(int argc, char const *argv[])
{
	char buf[30];
	char *ape;
	printf("printf : 0x%lx\n", &printf);
	puts("AAAA");
	gets(buf);
	return 0;
}