// Copyright 2022 The howijd.network Authors
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file.

package spec

type Specification struct {
	HeaderSize     int
	Version        uint16
	MinimumVersion uint16
	Magic          [4]byte
	Delimiter      [2]byte
	MagicDate      uint64
	TestFiles      map[string]bool // path => is valid
}

var Latest = V1
