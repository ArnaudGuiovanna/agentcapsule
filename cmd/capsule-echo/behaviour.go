//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"syscall"
)

// A test behaviour, chosen by the harness's entrypoint arguments: a KVM test
// packs this binary as a registry harness to check a platform limit (CAP-03,
// ADR 012). Without arguments, the harness behaves normally.
//
//	crash-at-boot          exits at once, before serving: the guest stops.
//	flood-volume <bytes>   serves normally, and on an ordinary boot also
//	                       writes its data directory as fast as it can,
//	                       <bytes> per write, each followed by fdatasync.
type behaviour struct {
	crashAtBoot bool
	floodChunk  int
}

// floodSpan is how much of the flood file is rewritten, again and again, so
// that the volume never fills.
const floodSpan = 32 << 20

var errCrashAtBoot = errors.New("crash at boot (test behaviour)")

func parseBehaviour(args []string) (behaviour, error) {
	switch {
	case len(args) == 0:
		return behaviour{}, nil
	case len(args) == 1 && args[0] == "crash-at-boot":
		return behaviour{crashAtBoot: true}, nil
	case len(args) == 2 && args[0] == "flood-volume":
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 512 || n > 8<<20 || floodSpan%n != 0 {
			return behaviour{}, errors.New("invalid flood write size")
		}
		return behaviour{floodChunk: n}, nil
	}
	return behaviour{}, errors.New("unknown test behaviour")
}

// flood rewrites the first floodSpan bytes of path, chunk bytes per write,
// each write made durable with fdatasync, until ctx ends or a write fails.
func flood(ctx context.Context, path string, chunk int) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, chunk)
	for offset := int64(0); ctx.Err() == nil; offset = (offset + int64(chunk)) % floodSpan {
		buf[0]++
		if _, err = f.WriteAt(buf, offset); err != nil {
			return err
		}
		if err = syscall.Fdatasync(int(f.Fd())); err != nil {
			return err
		}
	}
	return nil
}
