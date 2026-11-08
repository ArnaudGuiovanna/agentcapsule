//go:build linux && cgo

package volumestore

/*
#cgo LDFLAGS: -l:libcryptsetup.so.12
#include <libcryptsetup.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

static void ac_quiet(int level, const char *message, void *usrptr) {}
static void ac_configure(void) {
    crypt_set_log_callback(NULL, ac_quiet, NULL);
    // libcryptsetup otherwise opens a second description and flocks it,
    // deadlocking with our lifetime flock. All calls in this package run
    // under our stronger journal + inode locks, including the whole format.
    // This process must not use unguarded libcryptsetup entry points elsewhere.
    crypt_metadata_locking(NULL, 0);
}

static int ac_luks_begin(const char *path, const char *uuid, struct crypt_device **result) {
    struct crypt_device *cd = NULL;
    int rc = crypt_init(&cd, path);
    if (rc < 0) return rc;
    crypt_set_log_callback(cd, ac_quiet, NULL);
    // The input is a random 256-bit machine secret, never a user password.
    struct crypt_pbkdf_type pbkdf = {
        .type = CRYPT_KDF_ARGON2ID, .time_ms = 100,
        .max_memory_kb = 65536, .parallel_threads = 1
    };
    struct crypt_params_luks2 params = {.pbkdf = &pbkdf, .sector_size = 512};
    rc = crypt_format(cd, CRYPT_LUKS2, "aes", "xts-plain64", uuid, NULL, 64, &params);
    if (rc < 0) crypt_free(cd);
    else *result = cd;
    return rc;
}

static int ac_luks_check(const char *path, const char *uuid, const char *key, size_t keylen) {
    struct crypt_device *cd = NULL;
    int rc = crypt_init(&cd, path);
    if (rc < 0) return rc;
    crypt_set_log_callback(cd, ac_quiet, NULL);
    rc = crypt_load(cd, CRYPT_LUKS2, NULL);
    if (rc == 0 && (!crypt_get_uuid(cd) || strcmp(crypt_get_uuid(cd), uuid) ||
        !crypt_get_cipher(cd) || strcmp(crypt_get_cipher(cd), "aes") ||
        !crypt_get_cipher_mode(cd) || strcmp(crypt_get_cipher_mode(cd), "xts-plain64") ||
        crypt_get_volume_key_size(cd) != 64 || crypt_get_sector_size(cd) != 512)) rc = -EINVAL;
    // NULL mapping name checks the key only; it never creates a host mapping.
    if (rc == 0) rc = crypt_activate_by_passphrase(cd, NULL, CRYPT_ANY_SLOT, key, keylen, 0);
    crypt_free(cd);
    return rc < 0 ? rc : 0;
}
*/
import "C"

import (
	"runtime"
	"unsafe"
)

func init() { C.ac_configure() }

// Both operations run in the process owning the journal and volume flocks.
// No child can keep formatting after this process dies and releases its locks.
// libcryptsetup releases its key buffers with crypt_free before returning.
func luks(path, uuid string, key []byte, format bool, afterHeader func()) error {
	p, u := C.CString(path), C.CString(uuid)
	defer C.free(unsafe.Pointer(p))
	defer C.free(unsafe.Pointer(u))
	var rc C.int
	if format {
		var cd *C.struct_crypt_device
		rc = C.ac_luks_begin(p, u, &cd)
		if rc == 0 {
			defer C.crypt_free(cd)
			if afterHeader != nil {
				afterHeader()
			}
			rc = C.crypt_keyslot_add_by_volume_key(cd, C.CRYPT_ANY_SLOT, nil, 0,
				(*C.char)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
		}
	} else {
		rc = C.ac_luks_check(p, u, (*C.char)(unsafe.Pointer(&key[0])), C.size_t(len(key)))
	}
	runtime.KeepAlive(key)
	if rc < 0 {
		return ErrLUKS
	}
	return nil
}
