/*

clang++ -fsanitize=address,fuzzer libfuzzer-libpurple.cpp
./libpurple/.libs/libpurple.a $(pkg-config --libs --cflags dbus-glib-1 dbus-1
gio-2.0 glib-2.0 gobject-2.0 gmodule-2.0) -lxml2  -lresolv -lidn -lpthread
*/

#include "libpurple/util.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  char *foo;
  char *bar;
  char *tmp;
  int i;

  foo = (char *)malloc(Size + 1);

  memcpy(foo, Data, Size);
  foo[Size] = 0;

  tmp = purple_utf8_salvage(foo);

  if (tmp == 0) {
    free(foo);
    return 0;
  }

  bar = purple_markup_linkify(tmp);

  if (bar != 0)
    free(bar);
  if (tmp != 0)
    free(tmp);

  free(foo);
  return 0;
}
