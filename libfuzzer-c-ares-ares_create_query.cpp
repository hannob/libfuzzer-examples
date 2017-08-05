/* libfuzzer example for c-ares function ares_create_query()

   This quickly finds CVE-2016-5180 in c-ares 1.10.0.
*/
#include <arpa/nameser.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ares.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned char *buf;
  int buflen;
  char *inp = (char *)malloc(size + 1);
  inp[size] = 0;
  memcpy(inp, data, size);

  ares_create_query((const char *)inp, ns_c_in, ns_t_a, 0x1234, 0, &buf,
                    &buflen, 0);

  free(buf);
  free(inp);
  return 0;
}
