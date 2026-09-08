//go:build linux

package ops

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/pkg/errors"
)

// errRewriteUnimplemented is returned by rewriteExecThroughEmulator until the
// argv-rewrite step is completed (see the package notes in
// exec_binfmt_seccomp_linux.go). Callers treat it as "fall back to the native
// exec attempt", which preserves pre-feature behavior for foreign binaries.
var errRewriteUnimplemented = errors.New("seccomp emulator redirect not yet wired to argv rewrite")

// openTargetFile opens a path as observed from inside the target process's
// mount namespace, using /proc/<pid>/root so that the emulator mount and the
// container rootfs resolve correctly.
func openTargetFile(pid int, path string) (*os.File, error) {
	// #nosec G304 -- path originates from the traced process; it is only read
	// to inspect the ELF header and never executed here.
	return os.Open(filepath.Join("/proc", strconv.Itoa(pid), "root", path))
}

func itoa(v int) string {
	return strconv.Itoa(v)
}

// rewriteExecThroughEmulator makes the pending execve in the target process go
// through emulatorPath instead of the original binary.
//
// The intended mechanism is:
//   - SECCOMP_IOCTL_NOTIF_ADDFD the (already in-container) emulator, or write
//     the emulator path plus a rebuilt argv into a scratch region of the
//     target's memory via /proc/<pid>/mem, then
//   - point the execve filename/argv registers at the rewritten values before
//     responding with SECCOMP_USER_NOTIF_FLAG_CONTINUE.
//
// This is the remaining, kernel- and architecture-specific piece of
// https://github.com/moby/buildkit/issues/2873 and is validated through
// integration tests with the patched binfmt emulators rather than unit tests.
// Until it lands, foreign binaries fall back to the previous behavior.
func rewriteExecThroughEmulator(pid int, notif seccompNotif, emulatorPath string) error {
	_ = pid
	_ = notif
	_ = emulatorPath
	return errRewriteUnimplemented
}
