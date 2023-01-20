#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/mman.h>

#define CODE_LENGTH 0x500000
#define CODE_START 0x13370000

#define TIME 10

int main(int argc, char *argv[])
{
	int i;
	int temp;
	FILE* fp = fopen("RNG", "wb");
  	srand(atoi(argv[1]));
  	for(i = 0; i < CODE_LENGTH / 4; i++) {
  		temp = rand();
    	fwrite(&temp, sizeof(int), 1, fp);
  	}
  	fclose(fp);
  	return(0);
}