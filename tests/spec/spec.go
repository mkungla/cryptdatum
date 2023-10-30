// © 2023 Happy SDK Authors
// Apache License 2.0

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
