#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>

#define CODE_LEN 7
#define INPUT_LEN (CODE_LEN+1)

char input[INPUT_LEN];
char passwd[CODE_LEN];

void pwnme() {
  void *addr = mmap(NULL, 0x1000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  *(__int128*)addr = *(__int128*)passwd;
  uint8_t *ptr = addr;
  for (; ptr != addr + CODE_LEN-2; ptr++)
    *(ptr+2) ^= *(ptr+1) ^ *ptr;
  void (*fun)() = (void*)ptr;
  fun();
}

int main() {
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  int fd = open("/dev/urandom", 0);
  read(fd, passwd, CODE_LEN);
  close(fd);
  puts("Give me the secret");
  read(0, input, INPUT_LEN + CODE_LEN);
  if (strcmp(input, passwd) == 0) {
    puts("Good luck");
    pwnme();
  }
  return 0;
}
