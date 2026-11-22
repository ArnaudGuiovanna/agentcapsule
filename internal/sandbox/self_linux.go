//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Self reports whether this process is the program that RunSelf started as
// name. A package calls it from an init function, then runs its program and
// exits: the rest of this executable never runs there. Self first checks
// that the process is confined as RunSelf confines it, and adds a filter
// that refuses to execute any program; a process started under the name in
// any other way exits at once with status 125. Self returns false in every
// other process.
func Self(name string) bool {
	if len(os.Args) == 0 || os.Args[0] != name || !selfName(name) {
		return false
	}
	if err := selfConfined(); err != nil {
		fmt.Fprintln(os.Stderr, "sandbox:", name+":", err)
		os.Exit(125)
	}
	return true
}

// selfConfined fails unless this process is PID 1 of its own namespace,
// under a seccomp filter with no_new_privs, without any capability, then
// adds the filter that refuses execve and execveat to every thread.
func selfConfined() error {
	if os.Getpid() != 1 {
		return errors.New("not started by RunSelf: not PID 1 of its own namespace")
	}
	// Read without the os package, which would start the runtime's poller
	// (epoll), a call this program needs nowhere else.
	fd, err := unix.Open("/proc/self/status", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("/proc/self/status: %w", err)
	}
	b := make([]byte, 0, 8192)
	for len(b) < cap(b) {
		n, err := unix.Read(fd, b[len(b):cap(b)])
		if err == unix.EINTR {
			continue
		}
		if err != nil || n == 0 {
			break
		}
		b = b[:len(b)+n]
	}
	unix.Close(fd)
	want := map[string]string{"NoNewPrivs": "1", "Seccomp": "2", "CapInh": "0000000000000000", "CapPrm": "0000000000000000",
		"CapEff": "0000000000000000", "CapBnd": "0000000000000000", "CapAmb": "0000000000000000"}
	for line := range strings.Lines(string(b)) {
		key, value, _ := strings.Cut(line, ":")
		if v, ok := want[key]; ok && strings.TrimSpace(value) == v {
			delete(want, key)
		}
	}
	if len(want) != 0 {
		return errors.New("not started by RunSelf: not confined")
	}
	prog, err := filterProgram(noExec())
	if err != nil {
		return fmt.Errorf("seccomp: %w", err)
	}
	fprog := unix.SockFprog{Len: uint16(len(prog)), Filter: &prog[0]}
	// TSYNC: on every thread of the process, which the runtime started.
	if r, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&fprog))); e != 0 || r != 0 {
		return fmt.Errorf("seccomp: thread %d: %v", r, e)
	}
	return nil
}
