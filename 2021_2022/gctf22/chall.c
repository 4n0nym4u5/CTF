#include <stdio.h>

int main(int argc, char const *argv[])
{
	char *a=0xdeadbeef, *b=0xcafebabe;
	*a=0xaaaabbbb;
	*b=0xaaaadddd;
	return 0;
}