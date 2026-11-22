//go:build linux && cgo

package volumestore

/*
#include <libcryptsetup.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static void ac_check_quiet(int level, const char *message, void *usrptr) {}

// ac_check_load loads the LUKS2 header of path, and gives its metadata as
// JSON, which *cd owns. The program runs before this package's other init
// (ac_configure): it turns libcryptsetup's metadata locks off itself; the
// container is a copy that nothing else opens.
static int ac_check_load(const char *path, struct crypt_device **result, const char **json) {
    struct crypt_device *cd = NULL;
    crypt_set_log_callback(NULL, ac_check_quiet, NULL);
    crypt_metadata_locking(NULL, 0);
    int rc = crypt_init(&cd, path);
    if (rc < 0) return rc;
    crypt_set_log_callback(cd, ac_check_quiet, NULL);
    rc = crypt_load(cd, CRYPT_LUKS2, NULL);
    if (rc == 0) rc = crypt_dump_json(cd, json, 0);
    if (rc < 0) crypt_free(cd);
    else *result = cd;
    return rc;
}

// ac_check_volume: the container is the volume's (its UUID), with the
// platform's cipher, key size and sector size.
static int ac_check_volume(struct crypt_device *cd, const char *uuid) {
    if (!crypt_get_uuid(cd) || strcmp(crypt_get_uuid(cd), uuid) ||
        !crypt_get_cipher(cd) || strcmp(crypt_get_cipher(cd), "aes") ||
        !crypt_get_cipher_mode(cd) || strcmp(crypt_get_cipher_mode(cd), "xts-plain64") ||
        crypt_get_volume_key_size(cd) != 64 || crypt_get_sector_size(cd) != 512) return -EINVAL;
    return 0;
}

// ac_check_key: a NULL mapping name checks the key only; it never creates a
// mapping.
static int ac_check_key(struct crypt_device *cd, const char *key, size_t keylen) {
    int rc = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, key, keylen, 0);
    return rc < 0 ? rc : 0;
}
*/
import "C"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"time"
	"unsafe"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
	"golang.org/x/sys/unix"
)

// ErrHeader: the container's LUKS2 header is not one the platform creates
// (luks_header.go): the check refused it before any key derivation.
var ErrHeader = fmt.Errorf("%w: %v", ErrLUKS, errShape)

// luksCheckProgram is the confined program of CheckContainer (S-21):
// libcryptsetup parses a header the guest may have written, so it runs in
// the sandbox, never in the worker.
const luksCheckProgram = "agentcapsule-luks-check"

// The answers of the confined check, each on one line of its output.
const (
	answerOpen   = "open"   // the key opens the container's key slot
	answerClosed = "closed" // not a LUKS2 container, not the volume's, or not its key
	answerHeader = "header" // a header of another shape than the platform's
)

// The bounds of one check: 4 passes of Argon2id over 64 MiB take about
// 0.1 s, and the digest as much; a header the platform creates never needs
// more than a few seconds of processor time.
const (
	checkTimeout = 30 * time.Second
	checkCPU     = 10 * time.Second
)

func init() {
	if sandbox.Self(luksCheckProgram) {
		os.Exit(luksCheck())
	}
}

// luksCheck is the confined program: the expected UUID is its argument, the
// key its standard input, the container its descriptor 3. It writes its
// answer, and fails (status 2) only on a malformed call. It uses no os
// file, so that the runtime starts no poller.
func luksCheck() int {
	if len(os.Args) != 2 || len(os.Args[1]) != 36 {
		return 2
	}
	key := make([]byte, 33)
	defer clear(key)
	n := 0
	for n < len(key) {
		r, err := unix.Read(0, key[n:])
		if err == unix.EINTR {
			continue
		}
		if err != nil || r == 0 {
			break
		}
		n += r
	}
	if n != 32 {
		return 2
	}
	answer := checkLoaded(sandbox.ImagePath, os.Args[1], key[:32])
	if _, err := unix.Write(1, []byte(answer+"\n")); err != nil {
		return 2
	}
	return 0
}

// checkLoaded is the check, in the confined program.
func checkLoaded(path, uuid string, key []byte) string {
	p, u := C.CString(path), C.CString(uuid)
	defer C.free(unsafe.Pointer(p))
	defer C.free(unsafe.Pointer(u))
	var cd *C.struct_crypt_device
	var metadata *C.char
	if C.ac_check_load(p, &cd, &metadata) < 0 {
		return answerClosed
	}
	defer C.crypt_free(cd)
	if platformHeader([]byte(C.GoString(metadata))) != nil {
		return answerHeader
	}
	if C.ac_check_volume(cd, u) < 0 {
		return answerClosed
	}
	rc := C.ac_check_key(cd, (*C.char)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	runtime.KeepAlive(key)
	if rc < 0 {
		return answerClosed
	}
	return answerOpen
}

// CheckContainer checks that the file at path is the LUKS2 container of
// volumeID and that key opens its key slot: a header of the platform's shape
// (ErrHeader otherwise), the volume's UUID, cipher, key size and sector
// size, then the key (a restore test, OPR-5). The header may come from the
// guest, so libcryptsetup reads it confined by sb (package sandbox), as the
// program luksCheckProgram of this executable, never in this process: the
// key reaches it through a pipe, and a header of the platform's shape bounds
// the key derivation. It maps nothing and never unlocks the payload: the
// volume opens only in its guest (product.md). path must be a scratch copy,
// never an archive or a volume in use; the check opens it read-only.
func CheckContainer(ctx context.Context, sb sandbox.Options, path, volumeID string, key []byte) error {
	if !identifier(volumeID, "vol_") || len(key) != 32 {
		return ErrInput
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() {
		return ErrState
	}
	if sb.Timeout <= 0 {
		sb.Timeout = checkTimeout
	}
	if sb.CPU <= 0 {
		sb.CPU = checkCPU
	}
	out, err := sb.RunSelf(ctx, path, key, luksCheckProgram, Spec{VolumeID: volumeID}.uuid())
	if err != nil {
		return err
	}
	switch string(out) {
	case answerOpen + "\n":
		return nil
	case answerClosed + "\n":
		return ErrLUKS
	case answerHeader + "\n":
		return ErrHeader
	}
	return errors.New("volumestore: the confined LUKS2 check gave no answer")
}
