// makefat creates a Mach-O universal (fat) binary from multiple
// single-architecture Mach-O binaries. Pure Go, no cgo, no
// platform-specific tools (no lipo).
//
// Usage: makefat <output> <input1> <input2> [...]
package main

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

const (
	fatMagic  = 0xcafebabe
	alignBits = 14 // 2^14 = 16384 byte alignment (arm64 page size)
)

// fatHeader is the big-endian header at the start of a fat binary.
type fatHeader struct {
	Magic uint32
	NArch uint32
}

// fatArchEntry describes one architecture slice in the fat binary.
type fatArchEntry struct {
	CPUType    uint32
	CPUSubtype uint32
	Offset     uint32
	Size       uint32
	Align      uint32
}

func main() {
	if len(os.Args) < 4 {
		fmt.Fprintf(os.Stderr, "Usage: makefat <output> <input1> <input2> [...]\n")
		os.Exit(1)
	}

	outputPath := os.Args[1]
	inputPaths := os.Args[2:]

	type archSlice struct {
		cpuType    uint32
		cpuSubtype uint32
		data       []byte
	}

	var slices []archSlice
	seen := make(map[uint32]string)

	for _, path := range inputPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: read %s: %v\n", path, err)
			os.Exit(1)
		}

		f, err := macho.NewFile(bytes.NewReader(data))
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: parse %s as Mach-O: %v\n", path, err)
			os.Exit(1)
		}

		cpu := uint32(f.Cpu)
		if prev, ok := seen[cpu]; ok {
			fmt.Fprintf(os.Stderr, "error: duplicate CPU type 0x%x in %s and %s\n", cpu, prev, path)
			os.Exit(1)
		}
		seen[cpu] = path

		slices = append(slices, archSlice{
			cpuType:    cpu,
			cpuSubtype: uint32(f.SubCpu),
			data:       data,
		})
		f.Close()
	}

	// Calculate layout: header + arch descriptors, then aligned slices.
	headerSize := uint32(8 + len(slices)*20)
	align := uint32(1) << alignBits

	offset := roundUp(headerSize, align)
	entries := make([]fatArchEntry, len(slices))
	for i, s := range slices {
		entries[i] = fatArchEntry{
			CPUType:    s.cpuType,
			CPUSubtype: s.cpuSubtype,
			Offset:     offset,
			Size:       uint32(len(s.data)),
			Align:      alignBits,
		}
		offset = roundUp(offset+uint32(len(s.data)), align)
	}

	out, err := os.Create(outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: create %s: %v\n", outputPath, err)
		os.Exit(1)
	}
	defer out.Close()

	// Write fat header (big-endian).
	if err := binary.Write(out, binary.BigEndian, fatHeader{
		Magic: fatMagic,
		NArch: uint32(len(slices)),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "error: write header: %v\n", err)
		os.Exit(1)
	}

	// Write arch entries (big-endian).
	for _, e := range entries {
		if err := binary.Write(out, binary.BigEndian, e); err != nil {
			fmt.Fprintf(os.Stderr, "error: write arch entry: %v\n", err)
			os.Exit(1)
		}
	}

	// Write each slice at its aligned offset.
	for i, e := range entries {
		pos, _ := out.Seek(0, io.SeekCurrent)
		if gap := int64(e.Offset) - pos; gap > 0 {
			if _, err := out.Write(make([]byte, gap)); err != nil {
				fmt.Fprintf(os.Stderr, "error: write padding: %v\n", err)
				os.Exit(1)
			}
		}
		if _, err := out.Write(slices[i].data); err != nil {
			fmt.Fprintf(os.Stderr, "error: write slice %d: %v\n", i, err)
			os.Exit(1)
		}
	}

	if err := os.Chmod(outputPath, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "warning: chmod %s: %v\n", outputPath, err)
	}

	fmt.Printf("Created universal binary: %s (%d architectures)\n", outputPath, len(slices))
}

func roundUp(v, align uint32) uint32 {
	return (v + align - 1) & ^(align - 1)
}
