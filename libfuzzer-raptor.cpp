// clang -g -O1 libfuzzer-raptor.cpp -I/usr/include/raptor2
// -fsanitize=address,fuzzer -g libraptor2.a librdfa.a  -lcurl -lxml2 -lxslt

#include <raptor2.h>
#include <stdint.h>
#include <stdio.h>

static void print_triple(void *user_data, raptor_statement *triple) {
  raptor_statement_print_as_ntriples(triple, stdout);
  fputc('\n', stdout);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char *foo = "<xml>";
  raptor_world *world = NULL;
  raptor_parser *rdf_parser = NULL;
  unsigned char *uri_string;
  raptor_uri *uri, *base_uri;

  world = raptor_new_world();

  rdf_parser = raptor_new_parser(world, "rdfxml");

  raptor_parser_set_statement_handler(rdf_parser, NULL, print_triple);

  uri = raptor_new_uri(world, (const unsigned char *)"https://example.org/");
  raptor_parser_parse_start(rdf_parser, uri);
  raptor_parser_parse_chunk(rdf_parser, (const unsigned char *)data, size, 1);

  raptor_free_parser(rdf_parser);

  raptor_free_uri(uri);

  raptor_free_world(world);

  return 0;
}
