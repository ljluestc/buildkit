//go:build linux

package ops

import (
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// This file implements the emulator-selection mechanism described in
// https://github.com/moby/buildkit/issues/2873: instead of rewriting a
// container's entrypoint to invoke a single qemu emulator (which forces every
// binary in the container to share one architecture), a seccomp user
// notification listener is installed on execve(2)/execveat(2). For every exec
// the listener inspects the target binary, and if it is for a foreign
// architecture it transparently redirects the call through the matching
// embedded emulator that is bind-mounted into the container. Native binaries
// are allowed to continue unmodified, so binaries of mixed architectures can
// coexist in a single container.
//
// The pieces here that are architecture/kernel independent (ELF machine
// detection and emulator selection) are unit-tested directly. The ioctl-driven
// notification loop requires a seccomp-notify-capable kernel and the patched
// emulator binaries from https://github.com/tonistiigi/binfmt and is exercised
// through integration tests.

// elfMachineToArch maps the ELF e_machine value of a target binary to the
// normalized GOARCH used to locate the embedded emulator. Only the machines
// for which an embedded emulator exists are listed.
var elfMachineToArch = map[elf.Machine]string{
	elf.EM_AARCH64: "arm64",
	elf.EM_X86_64:  "amd64",
	elf.EM_386:     "386",
	elf.EM_ARM:     "arm",
	elf.EM_RISCV:   "riscv64",
	elf.EM_S390:    "s390x",
	elf.EM_PPC64:   "ppc64le",
}

// nativeELFMachine is the ELF machine of the host that buildkitd runs on.
// Binaries with this machine never need emulation.
var nativeELFMachine = hostELFMachine()

// detectELFMachine reads just enough of an ELF header from r to determine the
// target machine. It returns (0, nil) for files that are not ELF (for example
// scripts), which the caller treats as "run natively".
func detectELFMachine(r io.ReaderAt) (elf.Machine, error) {
	var ident [16]byte
	if _, err := r.ReadAt(ident[:], 0); err != nil {
		if err == io.EOF {
			return 0, nil
		}
		return 0, err
	}
	if ident[0] != '\x7f' || ident[1] != 'E' || ident[2] != 'L' || ident[3] != 'F' {
		// not an ELF binary (script, etc.) -> let the kernel handle it
		return 0, nil
	}

	var bo binary.ByteOrder
	switch elf.Data(ident[elf.EI_DATA]) {
	case elf.ELFDATA2LSB:
		bo = binary.LittleEndian
	case elf.ELFDATA2MSB:
		bo = binary.BigEndian
	default:
		return 0, errors.Errorf("unknown ELF data encoding %d", ident[elf.EI_DATA])
	}

	// e_machine is a uint16 at offset 18 in both ELF32 and ELF64.
	var m [2]byte
	if _, err := r.ReadAt(m[:], 18); err != nil {
		if err == io.EOF {
			return 0, nil
		}
		return 0, err
	}
	return elf.Machine(bo.Uint16(m[:])), nil
}

// emulatorForMachine returns the path to the embedded emulator required to run
// a binary of the given ELF machine, or "" if the binary can run natively (or
// is not an ELF binary at all). It returns an error only if an emulator is
// required but not installed.
func emulatorForMachine(m elf.Machine) (string, error) {
	if m == 0 || m == nativeELFMachine {
		return "", nil
	}
	arch, ok := elfMachineToArch[m]
	if !ok {
		// Unknown foreign machine; nothing we can do, let the kernel try.
		return "", nil
	}
	path, err := lookupEmulator(arch)
	if err != nil {
		return "", errors.Wrapf(err, "no emulator for %s (ELF machine %d)", arch, m)
	}
	return path, nil
}

func hostELFMachine() elf.Machine {
	f, err := elf.Open("/proc/self/exe")
	if err != nil {
		return 0
	}
	defer f.Close()
	return f.Machine
}

// seccompData mirrors struct seccomp_data (uapi/linux/seccomp.h).
type seccompData struct {
	nr                 int32
	arch               uint32
	instructionPointer uint64
	args               [6]uint64
}

// seccompNotif mirrors struct seccomp_notif.
type seccompNotif struct {
	id    uint64
	pid   uint32
	flags uint32
	data  seccompData
}

// seccompNotifResp mirrors struct seccomp_notif_resp.
type seccompNotifResp struct {
	id    uint64
	val   int64
	error int32
	flags uint32
}

const (
	// from uapi/linux/seccomp.h
	seccompUserNotifFlagContinue = 0x1

	// execve syscall arg registers we care about (arch-independent order in
	// seccomp_data.args): args[0] = filename pointer.
	nrExecveFilenameArg   = 0
	nrExecveatFilenameArg = 1 // execveat: args[0]=dirfd, args[1]=filename
)

// seccompEmulatorHandler serves a single container's seccomp notification fd,
// redirecting foreign-architecture execs through the appropriate emulator.
type seccompEmulatorHandler struct {
	// notifFD is the SCM_RIGHTS-received listener fd from runc.
	notifFD int
	// emulatorMount is the in-container path the emulators are mounted at.
	emulatorMount string

	once sync.Once
	stop chan struct{}
}

func newSeccompEmulatorHandler(notifFD int, emulatorMount string) *seccompEmulatorHandler {
	return &seccompEmulatorHandler{
		notifFD:       notifFD,
		emulatorMount: emulatorMount,
		stop:          make(chan struct{}),
	}
}

// Serve runs the notification loop until the fd is closed or Close is called.
func (h *seccompEmulatorHandler) Serve() error {
	for {
		select {
		case <-h.stop:
			return nil
		default:
		}
		notif, err := h.recv()
		if err != nil {
			if errors.Is(err, unix.ECANCELED) || errors.Is(err, unix.EBADF) {
				return nil
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return err
		}
		resp := h.handle(notif)
		if err := h.respond(resp); err != nil {
			// The target may have died between recv and respond; that races
			// are expected and non-fatal.
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return err
		}
	}
}

func (h *seccompEmulatorHandler) Close() {
	h.once.Do(func() { close(h.stop) })
}

// handle decides how to respond to a single execve notification. Native
// binaries (and non-ELF files) are continued unmodified; foreign binaries are
// redirected through the emulator by rewriting the target's argv in
// /proc/<pid>/mem before allowing the syscall to continue.
//
// It never blocks the target indefinitely: any error results in the syscall
// being allowed to continue so behavior degrades to the kernel default rather
// than deadlocking the build.
func (h *seccompEmulatorHandler) handle(notif seccompNotif) seccompNotifResp {
	resp := seccompNotifResp{id: notif.id, flags: seccompUserNotifFlagContinue}

	filenameArg := nrExecveFilenameArg
	if notif.data.nr == int32(unix.SYS_EXECVEAT) {
		filenameArg = nrExecveatFilenameArg
	}

	path, err := readTargetPath(int(notif.pid), notif.data.args[filenameArg])
	if err != nil {
		return resp // continue on error
	}

	f, err := openTargetFile(int(notif.pid), path)
	if err != nil {
		return resp
	}
	defer f.Close()

	machine, err := detectELFMachine(f)
	if err != nil {
		return resp
	}
	emu, err := emulatorForMachine(machine)
	if err != nil || emu == "" {
		return resp // native, unknown, or no emulator -> continue
	}

	// Foreign binary with an available emulator: rewrite the exec to go
	// through the emulator mounted in the container. The rewrite itself is
	// performed by injecting the emulator path into the target and pointing
	// the filename register at it; see rewriteExecThroughEmulator.
	if err := rewriteExecThroughEmulator(int(notif.pid), notif, filepath.Join(h.emulatorMount, filepath.Base(emu))); err != nil {
		return resp // fall back to native attempt on any failure
	}
	return resp
}

// recv performs SECCOMP_IOCTL_NOTIF_RECV.
func (h *seccompEmulatorHandler) recv() (seccompNotif, error) {
	var notif seccompNotif
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(h.notifFD),
		uintptr(unix.SECCOMP_IOCTL_NOTIF_RECV), uintptr(unsafe.Pointer(&notif)))
	if errno != 0 {
		return notif, errno
	}
	return notif, nil
}

// respond performs SECCOMP_IOCTL_NOTIF_SEND.
func (h *seccompEmulatorHandler) respond(resp seccompNotifResp) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(h.notifFD),
		uintptr(unix.SECCOMP_IOCTL_NOTIF_SEND), uintptr(unsafe.Pointer(&resp)))
	if errno != 0 {
		return errno
	}
	return nil
}

// readTargetPath reads a NUL-terminated path from the target process's memory
// at the given address via /proc/<pid>/mem.
func readTargetPath(pid int, addr uint64) (string, error) {
	f, err := os.Open(procMemPath(pid))
	if err != nil {
		return "", err
	}
	defer f.Close()

	buf := make([]byte, 0, 256)
	tmp := make([]byte, 256)
	off := int64(addr)
	for len(buf) < unix.PathMax {
		n, err := f.ReadAt(tmp, off)
		if n > 0 {
			if i := indexByte(tmp[:n], 0); i >= 0 {
				buf = append(buf, tmp[:i]...)
				return string(buf), nil
			}
			buf = append(buf, tmp[:n]...)
			off += int64(n)
		}
		if err != nil {
			return "", err
		}
	}
	return "", errors.New("exec path too long")
}

func procMemPath(pid int) string {
	return filepath.Join("/proc", itoa(pid), "mem")
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
