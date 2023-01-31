// go:build !cgo
//  +build !cgo

#include "../cryptdatum.h"
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#define _SIZE_BUF_LEN 100

const char* bool_str(bool value) {
  return value ? "true" : "false";
}

bool VERBOSE = false;

void pretty_size(uint64_t size, char* buf, size_t buf_len) {
  const char* units[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"};
  int i = 0;

  snprintf(buf, buf_len, "%" PRIu64 " %s", size, units[i]);
}

void print_header(cdt_header_t* header) {
  // // TIMESTAMP
  char created[_SIZE_BUF_LEN];
  struct tm tm;
  time_t t = (time_t)(header->timestamp / 1000000000);
  gmtime_r(&t, &tm);
  strftime(created, sizeof(created), "%Y-%m-%dT%H:%M:%S", &tm);
  snprintf(created + strlen(created), sizeof(created) - strlen(created), ".%09ldZ", header->timestamp % 1000000000);

  // SIZE
  char datumsize[_SIZE_BUF_LEN];
  pretty_size(header->size, datumsize, _SIZE_BUF_LEN);

  printf("+-------------------+-----------------------------------------+------------------------------------+\n");
  printf("| CRYPTDATUM        | SIZE: %-23s | CREATED: %35s | \n", datumsize, created);
	printf("+-------------------+----------+------------------------------+-------------+----------------------+\n");
	printf("| Field             | Size (B) | Description                  | Type        | Value                |\n");
	printf("+-------------------+----------+------------------------------+-------------+----------------------+\n");
	printf("| VERSION ID        | 2        | Version number               | 16-bit uint | %-20u |\n", header->version);
	printf("| FLAGS             | 8        | Flags                        | 64-bit uint | %-20"PRIu64 " |\n", header->flags);
	printf("| TIMESTAMP         | 8        | Timestamp                    | 64-bit uint | %-20"PRIu64 " |\n", header->timestamp);
	printf("| OPERATION COUNTER | 4        | Operation Counter            | 32-bit uint | %-20u |\n", header->opc);
	printf("| CHUNK SIZE        | 8        | Data chunk size              | 16-bit uint | %-20u |\n", header->chunk_size);
	printf("| NETWORK ID        | 8        | Network ID                   | 32-bit uint | %-20u |\n", header->network_id);
	printf("| SIZE              | 8        | Total payload size           | 64-bit uint | %-20"PRIu64 " |\n", header->size);
	printf("| CHECKSUM          | 8        | Datum checksum               | 64-bit uint | %-20"PRIu64 " |\n", header->checksum);
	printf("| COMPRESSION ALGO. | 2        | Compression algorithm        | 16-bit uint | %-20u |\n", header->compression);
	printf("| ENCRYPTION ALGO.  | 2        | Encryption algorithm         | 16-bit uint | %-20u |\n", header->encryption);
	printf("| SIGNATURE TYPE    | 2        | Signature type               | 16-bit uint | %-20u |\n", header->signature_type);
	printf("| SIGNATURE SIZE    | 2        | Signature size               | 16-bit uint | %-20u |\n", header->signature_size);
	printf("| METADATA SPEC     | 2        | Metadata specification       | 16-bit uint | %-20u |\n", header->metadata_spec);
	printf("| MEATADATA SIZE    | 4        | Metadata size                | 32-bit uint | %-20u |\n", header->metadata_size);
	printf("+-------------------+----------+------------------------------+-------------+----------------------+\n");
	printf("| DATUM FLAGS                  | Bits                         | Flag bit is set                    |\n");
	printf("+------------------------------+-------------------------------------------------------------------+\n");
	printf("| DATUM INVALID                | 1                            | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_INVALID));
	printf("| DATUM DRAFT                  | 2                            | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_DRAFT));
	printf("| DATUM EMPTY                  | 4                            | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_EMPTY));
	printf("| DATUM CHECKSUM               | 8                            | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_CHECKSUM));
	printf("| DATUM OPC                    | 16                           | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_OPC));
	printf("| DATUM COMPRESSED             | 32                           | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_COMPRESSED));
	printf("| DATUM ENCRYPTED              | 64                           | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_ENCRYPTED));
	printf("| DATUM EXTRACTABLE            | 128                          | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_EXTRACTABLE));
	printf("| DATUM SIGNED                 | 256                          | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_SIGNED));
	printf("| DATUM CHUNKED                | 512                          | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_CHUNKED));
	printf("| DATUM METADATA               | 1024                         | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_METADATA));
	printf("| DATUM COMPROMISED            | 2048                         | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_COMPROMISED));
	printf("| DATUM BIG ENDIAN             | 4096                         | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_BIG_ENDIAN));
	printf("| DATUM DATUM NETWORK          | 8192                         | %-5s                              |\n", bool_str(header->flags & CDT_DATUM_NETWORK));
	printf("+------------------------------+-------------------------------------------------------------------+\n");
}

int _cmd_file_has_header(char *filename)
{
  FILE *f = fopen(filename, "r");
  if (!f) {
    fprintf(stderr, "%s(%d): failed to open file\n", CDT_ERR_STR[CDT_ERROR_IO], CDT_ERROR_IO);
    return 1;
  }
  // Allocate a buffer to hold the header
  uint8_t *headerb = malloc(CDT_HEADER_SIZE);
  if (!headerb) {
    fprintf(stderr, "%s(%d): failed to allocate memory\n", CDT_ERR_STR[CDT_ERROR_IO], CDT_ERROR_IO);
    fclose(f);
    return 1;
  }
  // Read the header into the buffer
  size_t bytes_read = fread(headerb, 1, CDT_HEADER_SIZE, f);
  fclose(f);

  // Check header
  int exitcode = 0;
  if (bytes_read < CDT_HEADER_SIZE || has_header(headerb) != 1) {
    if (VERBOSE) fprintf(stderr, "%s(%d)\n", CDT_ERR_STR[CDT_ERROR_UNSUPPORTED_FORMAT], CDT_ERROR_UNSUPPORTED_FORMAT);
    exitcode = 1;
  }
  free(headerb);
  return exitcode;
}

int _cmd_file_has_valid_header(char *filename)
{
  FILE *f = fopen(filename, "r");
  if (!f) {
    fprintf(stderr, "%s(%d): failed to open file\n", CDT_ERR_STR[CDT_ERROR_IO], CDT_ERROR_IO);
    return 1;
  }
  // Allocate a buffer to hold the header
  uint8_t *headerb = malloc(CDT_HEADER_SIZE);
  if (!headerb) {
    fprintf(stderr, "%s(%d): failed to allocate memory\n", CDT_ERR_STR[CDT_ERROR_IO], CDT_ERROR_IO);
    fclose(f);
    return 1;
  }
  // Read the header into the buffer
  size_t bytes_read = fread(headerb, 1, CDT_HEADER_SIZE, f);
  fclose(f);

  int exitcode = 0;

  // Check that we read the full header
  if (bytes_read < CDT_HEADER_SIZE || has_header(headerb) != true) {
    if (VERBOSE) fprintf(stderr, "%s(%d)\n", CDT_ERR_STR[CDT_ERROR_UNSUPPORTED_FORMAT], CDT_ERROR_UNSUPPORTED_FORMAT);
    exitcode = 1;
  }
  if (exitcode == 0 && has_valid_header(headerb) != true) {
    if (VERBOSE) fprintf(stderr, "%s(%d)\n", CDT_ERR_STR[CDT_ERROR_INVALID_HEADER], CDT_ERROR_INVALID_HEADER);
    exitcode = 1;
  }

  free(headerb);
  return exitcode;
}

int _cmd_file_has_invalid_header(char *filename)
{
  FILE *f = fopen(filename, "r");
  if (!f) {
    fprintf(stderr, "%s(%d): failed to open file\n", CDT_ERR_STR[CDT_ERROR_IO], CDT_ERROR_IO);
    return 1;
  }
  // Allocate a buffer to hold the header
  uint8_t *headerb = malloc(CDT_HEADER_SIZE);
  if (!headerb) {
    fprintf(stderr, "%s(%d): failed to allocate memory\n", CDT_ERR_STR[CDT_ERROR_IO], CDT_ERROR_IO);
    fclose(f);
    return 1;
  }
  // Read the header into the buffer
  size_t bytes_read = fread(headerb, 1, CDT_HEADER_SIZE, f);
  fclose(f);

  int exitcode = has_valid_header(headerb);
  free(headerb);
  return exitcode;
}

int _cmd_file_info(char *filename)
{
  FILE *fp = fopen(filename, "r");
  if (!fp) {
    fprintf(stderr, "%s(%d): failed to open file\n", CDT_ERR_STR[CDT_ERROR_IO], CDT_ERROR_IO);
    return 1;
  }
  cdt_header_t header;
  cdt_error_t err = decode_header(cdt_fread, fp, &header);
  if (err != CDT_ERROR_NONE) {
    fprintf(stderr, "%s(%d): failed to decode header\n", CDT_ERR_STR[err], err);
    fclose(fp);
    return 1;
  }
  fclose(fp);

  print_header(&header);
  return 0;
}

int main(int argc, char *argv[])
{
  int opt;
  while ((opt = getopt(argc, argv, "v")) != -1) {
    switch (opt) {
      case 'v': VERBOSE = true; break;
      default:
        abort ();
    }
  }

  if (argc < 2) {
    fprintf(stderr, "%s(%d): no subcommand provided\n", CDT_ERR_STR[CDT_ERROR], CDT_ERROR);
    return 1;
  }

  if (strcmp(argv[optind], "file-has-header") == 0) {
    return _cmd_file_has_header(argv[optind+1]);
  } else if (strcmp(argv[optind], "file-has-valid-header") == 0) {
    return _cmd_file_has_valid_header(argv[optind+1]);
  } else if (strcmp(argv[optind], "file-has-invalid-header") == 0) {
    return _cmd_file_has_invalid_header(argv[optind+1]);
  } else if (strcmp(argv[optind], "file-info") == 0) {
    return _cmd_file_info(argv[optind+1]);
  } else {
    fprintf(stderr, "%s(%d): unknown subcommand '%s'\n", CDT_ERR_STR[CDT_ERROR], CDT_ERROR, argv[1]);
    return 1;
  }
  return 0;
}

