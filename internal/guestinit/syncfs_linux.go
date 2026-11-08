//go:build linux && cgo

package guestinit

/*
#define _GNU_SOURCE
#include <unistd.h>
*/
import "C"

import "os"

func syncFilesystem(f *os.File) error {
	code, err := C.syncfs(C.int(f.Fd()))
	if code != 0 {
		if err != nil {
			return err
		}
		return ErrGuest
	}
	return nil
}
