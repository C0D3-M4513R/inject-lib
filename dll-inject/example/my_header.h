#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


typedef struct FindPid {
  size_t len;
  uint32_t *arr;
  int16_t exitcode;
} FindPid;

int16_t eject(uint32_t pid, char *dll);

struct FindPid find_pid(char *name);

int16_t inject(uint32_t pid, char *dll);
