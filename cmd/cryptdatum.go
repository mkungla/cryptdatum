// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/howijd/cryptdatum"
)

var verboseFlag = flag.Bool("v", false, "verbose output")

func main() {
	flag.Parse()

	args := flag.Args()

	if len(args) < 2 {
		log.Fatal("error: no subcommand provided.")
	}

	switch args[0] {
	case "file-has-header":
		cmdFileHasHeader(args[1])
	case "file-has-valid-header":
		cmdFileHasValidHeader(args[1])
	case "file-has-invalid-header":
		cmdFileHasInvalidHeader(args[1])
	case "file-info":
		cmdFileInfo(args[1])
	default:
		log.Fatalf("invalid command %s", args[0])
	}
}

func exit(printalways bool, err error) {
	if printalways || *verboseFlag {
		fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(1)
}

func cmdFileHasHeader(file string) {
	ctd, err := os.Open(file)
	if err != nil {
		exit(true, fmt.Errorf("%w: %s", cryptdatum.ErrIO, err.Error()))
	}
	defer ctd.Close()
	headb := make([]byte, cryptdatum.HeaderSize)

	if _, err := ctd.Read(headb); err != nil && !errors.Is(err, io.EOF) {
		exit(false, fmt.Errorf("%w: %s", cryptdatum.ErrIO, err.Error()))
	}
	if !cryptdatum.HasHeader(headb) {
		exit(false, cryptdatum.ErrUnsupportedFormat)
	}
	os.Exit(0)
}

func cmdFileHasValidHeader(file string) {
	ctd, err := os.Open(file)
	if err != nil {
		exit(true, fmt.Errorf("%w: %s", cryptdatum.ErrIO, err.Error()))
	}
	defer ctd.Close()
	headb := make([]byte, cryptdatum.HeaderSize)

	if _, err := ctd.Read(headb); err != nil && !errors.Is(err, io.EOF) {
		exit(false, err)
	}
	if !cryptdatum.HasHeader(headb) {
		exit(false, cryptdatum.ErrUnsupportedFormat)
	}
	if !cryptdatum.HasValidHeader(headb) {
		exit(false, cryptdatum.ErrInvalidHeader)
	}
	os.Exit(0)
}

// Useful when looping over invalid file set
// and exit with status 1 when valid file is within the set.
func cmdFileHasInvalidHeader(file string) {
	ctd, err := os.Open(file)
	if err != nil {
		exit(true, fmt.Errorf("%w: %s", cryptdatum.ErrIO, err.Error()))
	}
	defer ctd.Close()
	headb := make([]byte, cryptdatum.HeaderSize)

	if _, err := ctd.Read(headb); err != nil && !errors.Is(err, io.EOF) {
		// exit(false, err)
		os.Exit(0)
	}
	if cryptdatum.HasValidHeader(headb) {
		// exit(false, cryptdatum.ErrInvalidHeader)
		os.Exit(1)
	}
	os.Exit(0)
}

func cmdFileInfo(file string) {
	ctd, err := os.Open(file)
	if err != nil {
		exit(true, err)
	}
	defer ctd.Close()

	header, err := cryptdatum.DecodeHeader(ctd)
	if err != nil {
		exit(true, fmt.Errorf("%w: failed to decode header", err))
	}
	printHeader(header)
	os.Exit(0)
}

func prettySize(size uint64) string {
	var units = []string{"B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}
	i := 0
	for size >= 1024 && i < 8 {
		size /= 1024
		i++
	}
	return fmt.Sprintf("%d %s", size, units[i])
}

func hhf(h cryptdatum.Header, flag uint64) bool {
	return h.Flags&cryptdatum.DatumFlag(flag) != 0
}

func printHeader(header cryptdatum.Header) {
	// swithc to text/template when the api is frozen
	datumsize := prettySize(header.Size)

	fmt.Printf("+-------------------+-----------------------------------------+------------------------------------+\n")
	fmt.Printf("| CRYPTDATUM        | SIZE: %-23s | CREATED: %35s | \n", datumsize, cryptdatum.Time(header.Timestamp).UTC().Format(time.RFC3339Nano))
	fmt.Printf("+-------------------+----------+------------------------------+-------------+----------------------+\n")
	fmt.Printf("| Field             | Size (B) | Description                  | Type        | Value                |\n")
	fmt.Printf("+-------------------+----------+------------------------------+-------------+----------------------+\n")
	fmt.Printf("| VERSION ID        | 2        | Version number               | 16-bit uint | %-20d |\n", header.Version)
	fmt.Printf("| FLAGS             | 8        | Flags                        | 64-bit uint | %-20d |\n", header.Flags)
	fmt.Printf("| TIMESTAMP         | 8        | Timestamp                    | 64-bit uint | %-20d |\n", header.Timestamp)
	fmt.Printf("| OPERATION COUNTER | 4        | Operation Counter            | 32-bit uint | %-20d |\n", header.OPC)
	fmt.Printf("| CHUNK SIZE        | 8        | Data chunk size              | 16-bit uint | %-20d |\n", header.ChunkSize)
	fmt.Printf("| NETWORK ID        | 8        | Network ID                   | 32-bit uint | %-20d |\n", header.NetworkID)
	fmt.Printf("| SIZE              | 8        | Total payload size           | 64-bit uint | %-20d |\n", header.Size)
	fmt.Printf("| CHECKSUM          | 8        | Datum checksum               | 64-bit uint | %-20d |\n", header.Checksum)
	fmt.Printf("| COMPRESSION ALGO. | 2        | Compression algorithm        | 16-bit uint | %-20d |\n", header.Compression)
	fmt.Printf("| ENCRYPTION ALGO.  | 2        | Encryption algorithm         | 16-bit uint | %-20d |\n", header.Encryption)
	fmt.Printf("| SIGNATURE TYPE    | 2        | Signature type               | 16-bit uint | %-20d |\n", header.SignatureType)
	fmt.Printf("| SIGNATURE SIZE    | 2        | Signature size               | 16-bit uint | %-20d |\n", header.SignatureSize)
	fmt.Printf("| METADATA SPEC     | 2        | Metadata specification       | 16-bit uint | %-20d |\n", header.MetadataSpec)
	fmt.Printf("| MEATADATA SIZE    | 4        | Metadata size                | 32-bit uint | %-20d |\n", header.MetadataSize)
	fmt.Printf("+-------------------+----------+------------------------------+-------------+----------------------+\n")
	fmt.Printf("| DATUM FLAGS                  | Bits                         | Flag bit is set                    |\n")
	fmt.Printf("+------------------------------+-------------------------------------------------------------------+\n")
	fmt.Printf("| DATUM INVALID                | 1                            | %-5t                              |\n", hhf(header, 1))
	fmt.Printf("| DATUM DRAFT                  | 2                            | %-5t                              |\n", hhf(header, 2))
	fmt.Printf("| DATUM EMPTY                  | 4                            | %-5t                              |\n", hhf(header, 4))
	fmt.Printf("| DATUM CHECKSUM               | 8                            | %-5t                              |\n", hhf(header, 8))
	fmt.Printf("| DATUM OPC                    | 16                           | %-5t                              |\n", hhf(header, 16))
	fmt.Printf("| DATUM COMPRESSED             | 32                           | %-5t                              |\n", hhf(header, 32))
	fmt.Printf("| DATUM ENCRYPTED              | 64                           | %-5t                              |\n", hhf(header, 64))
	fmt.Printf("| DATUM EXTRACTABLE            | 128                          | %-5t                              |\n", hhf(header, 128))
	fmt.Printf("| DATUM SIGNED                 | 256                          | %-5t                              |\n", hhf(header, 256))
	fmt.Printf("| DATUM CHUNKED                | 512                          | %-5t                              |\n", hhf(header, 512))
	fmt.Printf("| DATUM METADATA               | 1024                         | %-5t                              |\n", hhf(header, 1024))
	fmt.Printf("| DATUM COMPROMISED            | 2048                         | %-5t                              |\n", hhf(header, 2048))
	fmt.Printf("| DATUM BIG ENDIAN             | 4096                         | %-5t                              |\n", hhf(header, 4096))
	fmt.Printf("| DATUM DATUM NETWORK          | 8192                         | %-5t                              |\n", hhf(header, 8192))
	fmt.Printf("+------------------------------+-------------------------------------------------------------------+\n")
}
