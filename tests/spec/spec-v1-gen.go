// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

//go:build ignore

// This generates testdata. It can be invoked by running go generate
package main

import (
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/howijd/cryptdatum/tests/spec"
)

func main() {
	var testdataFuncs = []func() ([]byte, string, error){
		createValidHeaderMinimal,
		createValidHeaderFullFeatured,
		createInvalidHeaderFullFeatured,
	}

	for _, testdataFunc := range testdataFuncs {
		data, name, err := testdataFunc()
		fpath := filepath.Join("testdata/v1", name)
		if err != nil {
			log.Printf("failed to create testdata for, err=\"%s\" file=\"%s\"\n", err, fpath)
			os.Exit(1)
		}
		if err := os.WriteFile(fpath, data, 0640); err != nil {
			log.Printf("failed to save testdata file for, err=\"%s\" file=\"%s\"\n", err, fpath)
			os.Exit(1)
		}
	}
}

// createValidHeaderMinimal creates minimal valid header
func createValidHeaderMinimal() ([]byte, string, error) {
	const name = "valid-header-minimal.cdt"
	header := spec.Latest.NewMinimalValidHeader()
	return header, name, nil
}

func createValidHeaderFullFeatured() ([]byte, string, error) {
	const name = "valid-header-full-featured.cdt"
	header := spec.Latest.NewMinimalValidHeader()
	spec.V1.HeaderRemoveFlag(header, uint64(4))
	spec.V1.HeaderSetFlag(header, uint64(8|16|32|64|256|512|1024|8192))

	// Timestamp is Unix timestamp in nanoseconds spec v1 min date.
	ts := time.Date(2022, 5, 10, 4, 3, 2, 1, time.UTC).UnixNano()
	spec.V1.HeaderSetTimestamp(header, uint64(ts))
	spec.V1.HeaderSetOPC(header, 2)
	spec.V1.HeaderSetChunkSize(header, 3)
	spec.V1.HeaderSetNetworkID(header, 4)
	spec.V1.HeaderSetSize(header, 5)
	spec.V1.HeaderSetChecksum(header, 1234567890)
	spec.V1.HeaderSetCompression(header, 6)
	spec.V1.HeaderSetEncryption(header, 7)
	spec.V1.HeaderSetSignatureType(header, 8)
	spec.V1.HeaderSetSignatureSize(header, 9)
	spec.V1.HeaderSetMetadataSpec(header, 10)
	spec.V1.HeaderSetMetadataSize(header, 11)
	return header, name, nil
}

func createInvalidHeaderFullFeatured() ([]byte, string, error) {
	const name = "invalid-header-full-featured.cdt"
	header, _, err := createValidHeaderFullFeatured()
	if err != nil {
		return nil, name, err
	}

	// Cause late fail since metadata fields are checked in last priority
	spec.V1.HeaderRemoveFlag(header, 1024)
	return header, name, nil
}
