#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

int main(void) {
  int fd = open("/home/flag.txt", 0, 0);
  size_t pagesize = getpagesize();
  char * region = mmap(
    (void*) (pagesize * (1 << 20)), pagesize,
    PROT_READ, MAP_FILE|MAP_PRIVATE,
    fd, 0
  );
  fwrite(region, 1, pagesize, stdout);
  int unmap_result = munmap(region, pagesize);
  close(fd);
  return 0;
}