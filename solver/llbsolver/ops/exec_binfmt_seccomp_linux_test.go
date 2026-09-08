//go:build linux

package ops

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
)

// makeELFHeader builds a minimal ELF identification header carrying the given
// machine and byte order, enough for detectELFMachine.
func makeELFHeader(machine elf.Machine, bo binary.ByteOrder, class elf.Class, data elf.Data) []byte {
	b := make([]byte, 64)
	copy(b[:4], []byte("\x7fELF"))
	b[elf.EI_CLASS] = byte(class)
	b[elf.EI_DATA] = byte(data)
	bo.PutUint16(b[18:20], uint16(machine))
	return b
}

func TestDetectELFMachine(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    elf.Machine
		wantErr bool
	}{
		{
			name: "amd64 little endian 64",
			data: makeELFHeader(elf.EM_X86_64, binary.LittleEndian, elf.ELFCLASS64, elf.ELFDATA2LSB),
			want: elf.EM_X86_64,
		},
		{
			name: "arm64 little endian 64",
			data: makeELFHeader(elf.EM_AARCH64, binary.LittleEndian, elf.ELFCLASS64, elf.ELFDATA2LSB),
			want: elf.EM_AARCH64,
		},
		{
			name: "s390x big endian 64",
			data: makeELFHeader(elf.EM_S390, binary.BigEndian, elf.ELFCLASS64, elf.ELFDATA2MSB),
			want: elf.EM_S390,
		},
		{
			name: "arm little endian 32",
			data: makeELFHeader(elf.EM_ARM, binary.LittleEndian, elf.ELFCLASS32, elf.ELFDATA2LSB),
			want: elf.EM_ARM,
		},
		{
			name: "not an elf script",
			data: []byte("#!/bin/sh\necho hi\n"),
			want: 0,
		},
		{
			name: "too short",
			data: []byte{0x7f, 'E'},
			want: 0,
		},
		{
			name:    "bad data encoding",
			data:    func() []byte { b := makeELFHeader(elf.EM_X86_64, binary.LittleEndian, elf.ELFCLASS64, elf.ELFDATA2LSB); b[elf.EI_DATA] = 9; return b }(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := detectELFMachine(bytes.NewReader(tt.data))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, m)
		})
	}
}

func TestEmulatorForMachine(t *testing.T) {
	// Zero machine (non-ELF) and the native machine never need an emulator,
	// regardless of what is installed on the host.
	path, err := emulatorForMachine(0)
	require.NoError(t, err)
	require.Empty(t, path)

	if nativeELFMachine != 0 {
		path, err = emulatorForMachine(nativeELFMachine)
		require.NoError(t, err)
		require.Empty(t, path)
	}

	// An ELF machine we have no mapping for is treated as "let the kernel try"
	// rather than an error.
	path, err = emulatorForMachine(elf.EM_SPARCV9)
	require.NoError(t, err)
	require.Empty(t, path)
}

func TestElfMachineToArchMatchesQemuArchMap(t *testing.T) {
	// Every architecture we can select via ELF machine must have a
	// corresponding qemu arch alias so lookupEmulator can find the binary.
	for m, arch := range elfMachineToArch {
		_, ok := qemuArchMap[arch]
		require.Truef(t, ok, "arch %q for machine %d missing from qemuArchMap", arch, m)
	}
}
