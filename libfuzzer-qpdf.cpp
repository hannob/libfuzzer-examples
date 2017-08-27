/*

To compile:
clang++ -fsanitize=address -fsanitize-coverage=trace-pc-guard libfuzzer-qpdf.cpp
-Iinclude/ libqpdf/build/.libs/libqpdf.a libFuzzer.a -lz -ljpeg -o
libfuzzer-qpdf

*/
#include <qpdf/qpdf-c.h>
#include <stdint.h>
#include <sys/types.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  qpdf_data qpdf = qpdf_init();
  qpdf_read_memory(qpdf, "", (const char *)data, size, "");
  qpdf_cleanup(&qpdf);

  return 0;
}
