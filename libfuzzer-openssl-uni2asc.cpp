/* libfuzzer example for OpenSSL's uni2asc funciton
 *
 * Usage:
 * - compile openssl with coverage and asan:
 *   CC="clang -fsanitize-coverage=trace-pc-guard -fsanitize=address -g" \
 * ./config
 * - get libFuzzer.a (see libfuzzer.info)
 * - compile fuzz target:
 *   clang++ -fsanitize=address -fsanitize-coverage=trace-pc-guard \
 * libfuzzer-openssl-uni2asc.cpp libcrypto.a libFuzzer.a
 */

#include <openssl/pkcs12.h>
#include <stdint.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *out;
  out = OPENSSL_uni2asc((unsigned char *)data, size);
  if (out != NULL)
    free(out);
  return 0;
}

/* Uncomment to trigger bug in OpenSSL 1.0.2h and older, fixed here:
 * https://github.com/openssl/openssl/commit/39a43280316f1b9c45be5ac5b04f4f5c3f923686
 * Change zeros[4] to zeros[3] to get a different bug (read instead of write).
 */
/*
int main(int argc, char **argv) {
  unsigned char zeros[4] = {0};

  OPENSSL_uni2asc(zeros, 3);
  return 0;
}
*/
