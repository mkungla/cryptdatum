// go:build !cgo
//  +build !cgo

#include "cryptdatum.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

void test_has_valid_header_magic()
{
  // Test invalid magic number
  uint8_t header[CDT_HEADER_SIZE];
  memset(header, 0xFF, sizeof(header));

  uint16_t version_n = htobe16(1);
  uint64_t datum_draft_n = htobe64(CDT_DATUM_DRAFT);
  memcpy(header + 8, &version_n, 2);
  memcpy(header + 10, &datum_draft_n, 8);

  memcpy(header + CDT_HEADER_SIZE - 2, CDT_DELIMITER, 2);
  assert(has_valid_header(header) == 0);
}

void test_has_valid_header_too_small_data()
{
  uint8_t header[CDT_HEADER_SIZE-1];
  memcpy(header, CDT_MAGIC, 4);

  uint16_t version_n = htobe16(1);
  uint64_t datum_draft_n = htobe64(CDT_DATUM_DRAFT);
  memcpy(header + 4, &version_n, 2);
  memcpy(header + 6, &datum_draft_n, 8);

  memcpy(header + CDT_HEADER_SIZE-3, CDT_DELIMITER, 2);
  assert(has_valid_header(header) == 0);
}

void test_has_valid_header_delimiter()
{
  // Test invalid delimiter
  uint8_t header[CDT_HEADER_SIZE];
  memcpy(header, CDT_MAGIC, 4);

  uint16_t version_n = htobe16(1);
  uint64_t datum_draft_n = htobe64(CDT_DATUM_DRAFT);
  memcpy(header + 4, &version_n, 2);
  memcpy(header + 6, &datum_draft_n, 8);
  memcpy(header + CDT_HEADER_SIZE - 2, CDT_MAGIC, 2);
  assert(has_valid_header(header) == 0);
}

typedef struct {
const char *file_path;
int expected_result;
} TestCase;

void test_spec_V1_has_valid_header(const TestCase test_cases[], size_t num_cases)
{
  for (size_t i = 0; i < num_cases; i++) {
    FILE *f = fopen(test_cases[i].file_path, "r");
    if (!f) {
      fprintf(stderr, "error: failed to open file %s\n", test_cases[i].file_path);
      return;
    }
    uint8_t *header = malloc(CDT_HEADER_SIZE);
    if (!header) {
      fprintf(stderr, "error: failed to allocate memory\n");
      fclose(f);
      return;
    }
    size_t bytes_read = fread(header, 1, CDT_HEADER_SIZE, f);
    fclose(f);
    int result = has_valid_header(header);
    free(header);
    assert(result == test_cases[i].expected_result);
    printf("Test %s [%s]: %s\n", test_cases[i].file_path, result == test_cases[i].expected_result ? "PASSED" : "FAILED");
  }
}

int main(int argc, char *argv[])
{
  test_has_valid_header_magic();
  test_has_valid_header_too_small_data();
  test_has_valid_header_delimiter();

  // Spec files
  TestCase test_cases[] = {
  { "tests/spec/testdata/v1/valid-header-minimal.cdt", 1 },
  { "tests/spec/testdata/v1/valid-header-full-featured.cdt", 1 },
  { "tests/spec/testdata/v1/invalid-header-full-featured.cdt", 0 }
  };
  test_spec_V1_has_valid_header(test_cases, 3);
  return 0;
}
