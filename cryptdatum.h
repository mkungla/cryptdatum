//go:build !cgo
// +build !cgo

/**
 * @file cryptdatum.h
 * @brief Cryptdatum library header file
 *
 * This file contains the declarations for the Cryptdatum library,
 * which provides functions for reading and writing Cryptdatum data
 * structures.
 *
 * @author Marko Kungla
 * @copyright Copyright (c) 2022, The howijd.network Authors
 *
 * @see https://github.com/howijd/cryptdatum
 */
#ifndef CRYPTDATUM_H
#define CRYPTDATUM_H

#include <stddef.h>
#include <stdint.h>
#include <endian.h>

/**
 * @brief Size of a Cryptdatum header in bytes
 *
 * This constant defines the size of a Cryptdatum header in bytes. It can be
 * used by implementations of the Cryptdatum library to allocate sufficient
 * memory for a Cryptdatum header, or to check the size of a Cryptdatum header
 * that has been read from a stream.
 */
static const size_t CDT_HEADER_SIZE = 64;

/**
 * @brief Current version of the Cryptdatum format
 *
 * This constant defines the current version of the Cryptdatum format.
 * Implementations of the Cryptdatum library should set this value to 1
 * to indicate support for the current version of the format.
 */
static const uint8_t CDT_VERSION = 1;

/**
 * @brief Minimum version of the Cryptdatum format
 *
 * This constant defines the minimum version of the Cryptdatum format this
 * implementations of the Cryptdatum library supports.
 */
#define CDT_MIN_VERSION = 1

/**
 * @brief Magic number for Cryptdatum headers
 *
 * This constant defines the magic number that is used to identify Cryptdatum
 * headers. If the magic number field in a Cryptdatum header does not match
 * this value, the header should be considered invalid.
 */
static const uint8_t CDT_MAGIC[] = { 0xA7, 0xF6, 0xE5, 0xD4 };

/**
 * @brief Delimiter for Cryptdatum headers
 *
 * This constant defines the delimiter that is used to mark the end of a
 * Cryptdatum header. If the delimiter field in a Cryptdatum header does not
 * match this value, the header should be considered invalid.
 */
static const uint8_t CDT_DELIMITER[] = { 0xA6, 0xE5 };

/**
 * @brief this the minimum possible value for Timestamp header field.
*/
#define CDT_MAGIC_DATE 1652155382000000001

typedef enum uint64_t{
  CDT_DATUM_INVALID = (1 << 0),
  CDT_DATUM_DRAFT = (1 << 1),
  CDT_DATUM_EMPTY = (1 << 2),
  CDT_DATUM_CHECKSUM = (1 << 3),
  CDT_DATUM_OPC = (1 << 4),
  CDT_DATUM_COMPRESSED = (1 << 5),
  CDT_DATUM_ENCRYPTED = (1 << 6),
  CDT_DATUM_EXTRACTABLE = (1 << 7),
  CDT_DATUM_SIGNED = (1 << 8),
  CDT_DATUM_CHUNKED = (1 << 9),
  CDT_DATUM_METADATA = (1 << 10),
  CDT_DATUM_COMPROMISED = (1 << 11),
  CDT_DATUM_BIG_ENDIAN = (1 << 12),
  CDT_DATUM_NETWORK = (1 << 13)
} cdt_datum_flags_t;

#define _cdt_create_errors(error) \
        error(CDT_ERROR_NONE)   \
        error(CDT_ERROR)  \
        error(CDT_ERROR_IO)   \
        error(CDT_ERROR_EOF)  \
        error(CDT_ERROR_UNSUPPORTED_FORMAT)  \
        error(CDT_ERROR_INVALID_HEADER)  \

#define _cdt_generate_enum_value(ENUM) ENUM,
#define _cdt_generate_enum_string(STRING) #STRING,

typedef enum {
  _cdt_create_errors(_cdt_generate_enum_value)
} cdt_error_t;

static const char *CDT_ERR_STR[] = {
  _cdt_create_errors(_cdt_generate_enum_string)
};

/**
 * @brief Cryptdatum header structure
 *
 * The Cryptdatum header contains metadata about the data payload,
 * including the version, timestamp, and size.
 */
typedef struct
{
  uint16_t version;                 /**< Version indicates the version of the Cryptdatum format. */
  cdt_datum_flags_t flags;          /**< Cryptdatum format features flags to indicate which Cryptdatum features are used. */
  uint64_t timestamp;               /**< Timestamp is Unix timestamp in nanoseconds, */
  uint32_t opc;                     /**< OPC Operation Counter - Unique operation ID for the data. */
  uint16_t chunk_size;              /**< ChunkSize in kilobytes if DatumChunked is enabled */
  uint32_t network_id;              /**< NetworkID identifes the source network of the payload. When 0 no network is specified. */
  size_t size;                      /**< Total size (including header and signature) */
  uint64_t checksum;                /**< Checksum */
  uint16_t compression;             /**< Compression indicates the compression algorithm used, if any. */
  uint16_t encryption;              /**< Encryption indicates the encryption algorithm used, if any. */
  uint16_t signature_type;          /**< SignatureType indicates the signature type helping implementations to identify how the signature should be verified. */
  size_t signature_size;            /**< SignatureSize indicates the size of the signature, if any. */
  uint16_t metadata_spec;           /**< MetadataSpec is identifer which indentifies metadata format used if any is used. */
  size_t metadata_size;             /**< Metadata size. */
} cdt_header_t;

/**
 * @brief Check if the provided data contains a Cryptdatum header.
 *
 * This function checks if the provided data contains a Cryptdatum header. It looks for specific
 * header fields and checks their alignment, but does not perform any further validations. If the
 * data is likely to be Cryptdatum, the function returns true. Otherwise, it returns false.
 * If you want to verify the integrity of the header as well, use the has_valid_header function
 * or use decode_header and perform the validation yourself.
 *
 * The data argument should contain the entire Cryptdatum data, as a byte slice. The function will
 * read the first HeaderSize bytes of the slice to check for the presence of a header.
 *
 * @param data Pointer to the start of the Cryptdatum header
 * @return 1 if the header is valid, 0 if it is invalid
 */
int has_header(const uint8_t *data);

/**
 * @brief Check if the provided data contains a valid Cryptdatum header.
 *
 * This function checks if the provided data contains a valid Cryptdatum header. It verifies the
 * integrity of the header by checking the magic number, delimiter, and other fields. If the header
 * is valid, the function returns true. Otherwise, it returns false.
 *
 * The data argument can contain any data as a byte slice, but should be at least CDT_HEADER_SIZE in length
 * and start with the header. The function will read the first HeaderSize bytes of the slice to
 * validate the header. If the data slice is smaller than CDT_HEADER_SIZE bytes, the function will
 * return false, as the header is considered incomplete.
 *
 * @param data Pointer to the start of the Cryptdatum header
 * @return 1 if the header is valid, 0 if it is invalid
 */
int has_valid_header(const uint8_t *data);

/**
 * @brief Function pointer type for a reader function that reads a byte array from a data source.
 *
 * The reader function should take a `void*` as an argument and return a pointer to an array of
 * `uint8_t` representing the bytes of data read from the source.
 */
typedef size_t (*cdt_reader_fn)(uint8_t *data, size_t size, size_t nmemb, void* stream);

/**
 * @brief Decodes the header information of a Cryptdatum data without decoding the entire data.
 * Caller is responsible to close the source e.g FILE
 *
 * @param[in] r Function pointer to a reader function that reads a byte array from the data source.
 * @param[in] source Pointer to the data source e.g FILE.
 * @param[out] header Pointer to a struct to receive the decoded header information.
 * @return An error code indicating the result of the operation.
 */
cdt_error_t decode_header(cdt_reader_fn read, void* source, cdt_header_t* header);

/**
 * @brief Reader implementation to read cryptdatum from file source.
 *
 * @param[out] buffer Pointer to the buffer to store the read data.
 * @param[in] size Size of each element in the buffer.
 * @param[in] nmemb Number of elements to read.
 * @param[in] fp Pointer to the file to read from.
 * @return The number of elements read, or 0 if an error occurred.
 */
size_t cdt_fread(uint8_t *buffer, size_t size, size_t nmemb, void* fp);

#endif // CRYPTDATUM_H
