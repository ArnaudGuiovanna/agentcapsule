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
//	                       <bytes> per write (a multiple of 4 KiB), each
//	                       direct (O_DIRECT): past the page cache, it
//	                       reaches the drive at once and needs no flush.
//	fill-tmp <bytes>       before serving, writes up to <bytes> to /tmp; if
//	                       /tmp is full first, it removes the file and
//	                       serves, otherwise it exits: /tmp is not bounded.
//	text-only              serves normally but does not accept JSON content,
//	                       like a harness built before it existed.
//
// The hostile behaviours (hostile.go) push against the VM's other ceilings
// (RUN-007). The first three serve normally until 2 seconds after the
// harness first answers, then turn, until the guest stops:
//
//	burn-cpu               keeps every vCPU busy.
//	eat-memory             maps memory and writes every page of it, without
//	                       end: the guest's kernel must kill the harness.
//	fork-bomb              forks processes that only wait, until the guest
//	                       refuses, and tries again every 100 ms.
//	never-files            answers every invocation "working", loops on it,
//	                       and never files its outcome.
//
// One more (never_returns.go) holds its store (ADR 012, question 7):
//
//	never-returns          never returns from an invocation whose text says
//	                       "never return": it holds its store's write
//	                       transaction until the harness stops. It answers
//	                       other invocations as usual.
//
// One more (probe_corpus.go) reports the corpora it sees (ADR 023 §5):
//
//	probe-corpus           answers an event whose body is "probe-corpus"
//	                       with its view of /corpus: each mount's options,
//	                       marker, and whether a write or an execution
//	                       there succeeds. It echoes other events.
type behaviour struct {
	crashAtBoot bool
	floodChunk  int
	fillTmp     int64
	textOnly    bool
	modelSlots  bool
	// hostile names an entry of hostile, started after the first answer.
	hostile      string
	neverFiles   bool
	neverReturns bool
	probeCorpus  bool
}

var errTmpUnbounded = errors.New("/tmp took the whole fill (test behaviour)")

// fillTmp writes up to limit bytes in dir. It returns nil once the filesystem
// is full (ENOSPC) and errTmpUnbounded if it took them all. The file is
// removed either way.
func fillTmp(dir string, limit int64) error {
	f, err := os.CreateTemp(dir, "fill-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	buf := make([]byte, 1<<20)
	for written := int64(0); written < limit; {
		n, err := f.Write(buf[:min(int64(len(buf)), limit-written)])
		written += int64(n)
		if errors.Is(err, syscall.ENOSPC) {
			return nil
		}
		if err != nil {
			return err
		}
	}
	return errTmpUnbounded
}

// floodSpan is how much of the flood file is rewritten, again and again, so
// that the volume never fills.
const floodSpan = 32 << 20

var errCrashAtBoot = errors.New("crash at boot (test behaviour)")

func parseBehaviour(args []string) (behaviour, error) {
	switch {
	case len(args) == 0:
		return behaviour{}, nil
	case len(args) == 1 && args[0] == "model-stream-slots":
		return behaviour{modelSlots: true}, nil
	case len(args) == 1 && args[0] == "crash-at-boot":
		return behaviour{crashAtBoot: true}, nil
	case len(args) == 2 && args[0] == "flood-volume":
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 4096 || n > 8<<20 || n%4096 != 0 || floodSpan%n != 0 {
			return behaviour{}, errors.New("invalid flood write size")
		}
		return behaviour{floodChunk: n}, nil
	case len(args) == 2 && args[0] == "fill-tmp":
		n, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || n < 1<<20 || n > 2<<30 {
			return behaviour{}, errors.New("invalid fill size")
		}
		return behaviour{fillTmp: n}, nil
	case len(args) == 1 && args[0] == "text-only":
		return behaviour{textOnly: true}, nil
	case len(args) == 1 && hostile[args[0]] != nil:
		return behaviour{hostile: args[0]}, nil
	case len(args) == 1 && args[0] == "never-files":
		return behaviour{neverFiles: true}, nil
	case len(args) == 1 && args[0] == "never-returns":
		return behaviour{neverReturns: true}, nil
	case len(args) == 1 && args[0] == "probe-corpus":
		return behaviour{probeCorpus: true}, nil
	}
	return behaviour{}, errors.New("unknown test behaviour")
}

// flood rewrites the first floodSpan bytes of path, chunk bytes per write,
// until ctx ends or a write fails. The span is allocated first, so that no
// write allocates. Each write is direct, from a page-aligned buffer: the
// guest's page cache does not absorb it, and it reaches the drive as
// requests of its own bytes, with no flush. So the VMM moves exactly the
// bytes the flood writes, and a KVM test can count them (ADR 012).
func flood(ctx context.Context, path string, chunk int) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_DIRECT|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = syscall.Fallocate(int(f.Fd()), 0, 0, floodSpan); err != nil {
		return err
	}
	// An anonymous mapping is page-aligned, as O_DIRECT requires.
	buf, err := syscall.Mmap(-1, 0, chunk, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_ANON|syscall.MAP_PRIVATE)
	if err != nil {
		return err
	}
	defer syscall.Munmap(buf)
	for offset := int64(0); ctx.Err() == nil; offset = (offset + int64(chunk)) % floodSpan {
		buf[0]++
		if _, err = f.WriteAt(buf, offset); err != nil {
			return err
		}
	}
	return nil
}
