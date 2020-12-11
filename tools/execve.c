#include <stddef.h>
int main() {
  char* argv[] = { "", NULL };
  execve("/system/bin/sh", argv, NULL);
  return 1;
}
