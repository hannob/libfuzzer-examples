/* Compile together with libfuzzer stub to get executable that will pass
 * input file to the libfuzzer function.
 * With this you can combine the use of afl tools like afl-tmin to work
 * with libfuzzer stubs.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

int main(int argc, char **argv) {
  size_t s;
  FILE *f = fopen(argv[1], "rb");
  unsigned char *b;
  fseek(f, 0, SEEK_END);
  s = ftell(f);
  fseek(f, 0, SEEK_SET);

  b = (unsigned char *)malloc(s);
  fread(b, s, 1, f);
  fclose(f);

  LLVMFuzzerTestOneInput(b, s);

  free(b);
}
