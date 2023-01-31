// go:build !cgo
//  +build !cgo

/*
 * The Cryptdatum format is a powerful, flexible universal data format for 
 * storing data in a long-term compatible way across domains and with any 
 * encryption and compression algorithms. It consists of a 64-byte header 
 * that stores information about the data payload, followed by the data 
 * payload or 64-byte header followed by the optional metadata, signature, 
 * and then data payload. Cryptdatum is designed to be flexible enough to 
 * accommodate a variety of use cases, while still maintaining simplicity. 
 * Usage of all features used in the data can be determined by reading setting 
 * from different header flags and accompanying header fields.
 */

#include "cryptdatum.h"
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

const uint8_t empty[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

int has_header(const uint8_t *data)
{
  // Check for valid header size
  if (data == NULL) {
    return false;
  }
   // check magic and delimiter
  return (memcmp(data, CDT_MAGIC, 4) == 0 && memcmp(data + 62, CDT_DELIMITER, 2) == 0);
}

int has_valid_header(const uint8_t *data)
{
  if (has_header(data) != 1) {
    return false;
  }

  // check version is >= 1
  if (le16toh(*((uint16_t *)(data + 4))) < 1) {
    return false;
  }

  // break here if CDT_DATUM_DRAFT or CDT_DATUM_COMPROMISED is set
  uint64_t flags = le64toh(*((uint64_t *)(data + 6)));
  if (flags & CDT_DATUM_COMPROMISED) {
    return false;
  }
  if (flags & CDT_DATUM_DRAFT) {
    return true;
  }

  // It it was not a draft it must have timestamp
  if (le64toh(*((uint64_t *)(data + 14))) < CDT_MAGIC_DATE) {
    return false;
  }

  // CDT_DATUM_OPC is set then counter value must be gte 1
  if ((flags & CDT_DATUM_OPC && (le32toh(*((uint32_t *)(data + 22))) == 0)) ||  (!(flags & CDT_DATUM_OPC) && (le32toh(*((uint32_t *)(data + 22))) > 0))) {
    return false;
  }

  // CDT_DATUM_CHUNKED is set then chunk size value must be gte 1
  if ((flags & CDT_DATUM_CHUNKED && (le16toh(*((uint16_t *)(data + 26))) == 0)) || (!(flags & CDT_DATUM_CHUNKED) && (le16toh(*((uint16_t *)(data + 26))) > 0))) {
    return false;
  }

	// CDT_DATUM_NETWORK is set then network id value must be gte 1
  if ((flags & CDT_DATUM_NETWORK && (le32toh(*((uint32_t *)(data + 28))) == 0)) || (!(flags & CDT_DATUM_NETWORK) && (le32toh(*((uint32_t *)(data + 28))) > 0))) {
    return false;
  }
  
  // CDT_DATUM_EMPTY is set then size value must be 0
	// CDT_DATUM_EMPTY is not set then size value must be gte 1
  if ((flags & CDT_DATUM_EMPTY && (le64toh(*((uint64_t *)(data + 32))) > 0)) || (!(flags & CDT_DATUM_EMPTY) && le64toh(*((uint64_t *)(data + 32))) == 0)) {
    return false; 
  }

  // CDT_DATUM_CHECKSUM then Checksum must be set
  if ((flags & CDT_DATUM_CHECKSUM && memcmp(data + 40, empty, 8) == 0) || (!(flags & CDT_DATUM_CHECKSUM) && memcmp(data + 40, empty, 8) > 0)) {
    return false;
  }

  // CDT_DATUM_COMPRESSED compression algorithm must be set
  if (flags & CDT_DATUM_COMPRESSED && le16toh(*((uint16_t *)(data + 48))) == 0) {
    return false;
  }

  // CDT_DATUM_ENCRYPTED encryption algorithm must be set
  if (flags & CDT_DATUM_ENCRYPTED && le16toh(*((uint16_t *)(data + 50))) == 0) {
    return false;
  }


  // CDT_DATUM_SIGNED then Signature Type must be also set
  // however value of the signature Size may depend on Signature Type
  if ((flags & CDT_DATUM_SIGNED && le16toh(*((uint16_t *)(data + 52))) == 0) || (!(flags & CDT_DATUM_SIGNED) && (le16toh(*((uint16_t *)(data + 52))) > 0 || le16toh(*((uint16_t *)(data + 54))) > 0))) {
    return false;
  }

  // CDT_DATUM_METADATA MEATADATA SPEC  and MEATADATA SIZE
  if (flags & CDT_DATUM_METADATA && le16toh(*((uint16_t *)(data + 56))) == 0) {
    return false;
  }
  if (!(flags & CDT_DATUM_METADATA) && (le16toh(*((uint16_t *)(data + 56))) > 0 || le16toh(*((uint32_t *)(data + 58))) > 0)) {
    return false;
  }

  return true;
}

cdt_error_t decode_header(cdt_reader_fn read, void* source, cdt_header_t* header)
{
  // Allocate a buffer to hold the header
  uint8_t *headerb = malloc(CDT_HEADER_SIZE);
  size_t bytes_read = read(headerb, 1, CDT_HEADER_SIZE, source);
  if (bytes_read < CDT_HEADER_SIZE) {
    free(headerb);
    return CDT_ERROR_IO;
  }

  if (has_header(headerb) != 1) {
    return CDT_ERROR_UNSUPPORTED_FORMAT;
  }
  if (has_valid_header(headerb) != 1) {
    return CDT_ERROR_INVALID_HEADER;
  }

  // Parse the header
  header->version = le16toh(*((uint16_t*)(headerb + 4)));
  header->flags = le64toh(*((uint64_t*)(headerb + 6)));
  header->timestamp = le64toh(*((uint64_t*)(headerb + 14)));
  header->opc = le32toh(*((uint32_t*)(headerb + 22)));
  header->chunk_size = le16toh(*((size_t*)(headerb + 26)));
  header->network_id = le32toh(*((uint32_t*)(headerb + 28)));
  header->size = le64toh(*((uint64_t*)(headerb + 32)));
  header->checksum = le64toh(*((uint64_t*)(headerb + 40)));
  header->compression = le16toh(*((uint16_t*)(headerb + 48)));
  header->encryption = le16toh(*((uint16_t*)(headerb + 50)));
  header->signature_type = le16toh(*((uint16_t*)(headerb + 52)));
  header->signature_size = le16toh(*((size_t*)(headerb + 54)));
  header->metadata_spec = le16toh(*((uint16_t*)(headerb + 56)));
  header->metadata_size = le32toh(*((size_t*)(headerb + 58)));
  free(headerb);

  return CDT_ERROR_NONE;
}

size_t cdt_fread(uint8_t *buffer, size_t size, size_t nmemb, void* fp)
{
  // Check if the fp argument is a valid file pointer
  if (!fp || (uintptr_t)fp % __alignof__(FILE*) != 0 ||
    offsetof(FILE, _flags) != 0 || ((FILE*)fp)->_flags == 0) {
    return 0; // invalid file pointer
  }
  return fread(buffer, size, nmemb, fp);
}
