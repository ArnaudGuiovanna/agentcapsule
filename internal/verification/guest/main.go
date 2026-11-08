//go:build linux && amd64

// Test-only PID 1 for a disposable Firecracker storage lab. This is NOT the
// production capsule-init: its vsock endpoint deliberately exposes fault hooks.
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
	"github.com/mattn/go-sqlite3"
)

type command struct {
	Op, ID, Subject, Pause string
	Bytes                  int
}

type response struct {
	OK         bool           `json:"ok"`
	Error      string         `json:"error,omitempty"`
	SQLiteCode int            `json:"sqlite_code,omitempty"`
	Fenced     bool           `json:"fenced,omitempty"`
	Phase      string         `json:"phase,omitempty"`
	Replayed   bool           `json:"replayed,omitempty"`
	Data       map[string]any `json:"data,omitempty"`
}

func failure(err error) response {
	r := response{Error: err.Error(), Fenced: errors.Is(err, harnessstore.ErrFenced)}
	var e sqlite3.Error
	if errors.As(err, &e) {
		r.SQLiteCode = int(e.Code)
	}
	return r
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func mount(source, target, kind string, flags uintptr) {
	must(os.MkdirAll(target, 0700))
	must(syscall.Mount(source, target, kind, flags, ""))
}

// sockaddr_vm is the Linux UAPI layout for x86_64 (16 bytes). The standard
// library's Sockaddr conversion does not implement AF_VSOCK.
func listenVSock() int {
	fd, err := syscall.Socket(40, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	must(err)
	addr := struct {
		Family, Reserved uint16
		Port, CID        uint32
		Flags            uint8
		Zero             [3]byte
	}{Family: 40, Port: 5000, CID: ^uint32(0)}
	_, _, errno := syscall.Syscall(syscall.SYS_BIND, uintptr(fd), uintptr(unsafe.Pointer(&addr)), unsafe.Sizeof(addr))
	runtime.KeepAlive(addr)
	if errno != 0 {
		panic(errno)
	}
	must(syscall.Listen(fd, 16))
	return fd
}

func hold() {
	for {
		time.Sleep(time.Hour)
	}
}

func main() {
	if os.Getpid() != 1 {
		fmt.Fprintln(os.Stderr, "storage probe must run as guest PID 1")
		os.Exit(2)
	}
	mount("proc", "/proc", "proc", 0)
	mount("sysfs", "/sys", "sysfs", 0)
	mount("devtmpfs", "/dev", "devtmpfs", 0)
	must(os.MkdirAll("/tmp", 0700))
	mount("/dev/vda", "/data", "ext4", syscall.MS_NOATIME)
	ctx := context.Background()
	store, err := harnessstore.Open(ctx, "/data/state.db")
	must(err)
	db, err := sql.Open("sqlite3", "file:/data/state.db?_journal_mode=WAL&_synchronous=FULL&_busy_timeout=5000")
	must(err)
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS effects (id TEXT PRIMARY KEY, payload BLOB NOT NULL)")
	must(err)
	fd := listenVSock()
	fmt.Println("AGENTCAPSULE_STORAGE_READY")
	for {
		conn, _, errno := syscall.Syscall6(syscall.SYS_ACCEPT4, uintptr(fd), 0, 0, syscall.SOCK_CLOEXEC, 0, 0)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			panic(errno)
		}
		f := os.NewFile(conn, "vsock")
		var cmd command
		err := json.NewDecoder(f).Decode(&cmd)
		enc := json.NewEncoder(f)
		if err != nil {
			_ = enc.Encode(failure(err))
		} else {
			_ = enc.Encode(execute(ctx, store, db, enc, cmd))
		}
		_ = f.Close()
	}
}

func execute(ctx context.Context, store *harnessstore.Store, db *sql.DB, enc *json.Encoder, c command) response {
	switch c.Op {
	case "info":
		blocks, err := os.ReadDir("/sys/class/block")
		if err != nil {
			return failure(err)
		}
		names := []string{}
		for _, b := range blocks {
			if strings.HasPrefix(b.Name(), "vd") {
				names = append(names, b.Name())
			}
		}
		bootID, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
		if err != nil {
			return failure(err)
		}
		return response{OK: true, Data: map[string]any{"pid": os.Getpid(), "boot_id": strings.TrimSpace(string(bootID)), "block_devices": names}}
	case "apply":
		if c.Bytes < 0 || c.Bytes > 32<<20 {
			return failure(errors.New("invalid blob size"))
		}
		if c.Subject == "" {
			c.Subject = "agent/a"
		}
		e := harnessstore.Event{ID: c.ID, Subjects: []string{c.Subject}, Body: []byte(fmt.Sprintf("test-payload-size:%d", c.Bytes))}
		r, err := store.Apply(ctx, e, func(ctx context.Context, tx harnessstore.SQL) ([]byte, error) {
			if _, err := tx.ExecContext(ctx, "INSERT INTO effects(id,payload) VALUES (?,zeroblob(?))", c.ID, c.Bytes); err != nil {
				return nil, err
			}
			if c.Pause == "before_commit" {
				must(enc.Encode(response{OK: true, Phase: "before_commit"}))
				hold()
			}
			return []byte("committed:" + c.ID), nil
		})
		if err != nil {
			return failure(err)
		}
		if c.Pause == "after_commit" {
			must(enc.Encode(response{OK: true, Phase: "after_commit"}))
			hold()
		}
		return response{OK: true, Replayed: r.Replayed, Data: map[string]any{"result": string(r.Result)}}
	case "broken_split":
		// Deliberate negative control: independently commit an effect without the
		// inbox marker. Never reachable through the production Store API.
		if _, err := db.ExecContext(ctx, "INSERT INTO effects(id,payload) VALUES (?,zeroblob(1048576))", c.ID); err != nil {
			return failure(err)
		}
		must(enc.Encode(response{OK: true, Phase: "broken_effect_committed_without_marker"}))
		hold()
		panic("unreachable")
	case "fence":
		if err := store.Fence(ctx, c.Subject); err != nil {
			return failure(err)
		}
		return response{OK: true}
	case "inspect":
		var effects, markers, fences int
		for _, q := range []struct {
			sql string
			out *int
		}{
			{"SELECT COUNT(*) FROM effects", &effects},
			{"SELECT COUNT(*) FROM capsule_inbox", &markers},
			{"SELECT COUNT(*) FROM capsule_fences", &fences},
		} {
			if err := db.QueryRowContext(ctx, q.sql).Scan(q.out); err != nil {
				return failure(err)
			}
		}
		rows, err := db.QueryContext(ctx, "PRAGMA integrity_check")
		if err != nil {
			return failure(err)
		}
		defer rows.Close()
		checks := []string{}
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return failure(err)
			}
			checks = append(checks, s)
		}
		if err := rows.Err(); err != nil {
			return failure(err)
		}
		return response{OK: true, Data: map[string]any{"effects": effects, "markers": markers, "fences": fences, "integrity": checks}}
	case "fill":
		f, err := os.OpenFile("/data/fill", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return failure(err)
		}
		defer f.Close()
		var total int64
		block := make([]byte, 1<<20)
		for {
			n, err := f.Write(block)
			total += int64(n)
			if err != nil {
				if !errors.Is(err, syscall.ENOSPC) {
					return failure(err)
				}
				return response{OK: true, Data: map[string]any{"filled_bytes": total, "errno": "ENOSPC"}}
			}
		}
	case "unfill":
		if err := os.Remove("/data/fill"); err != nil {
			return failure(err)
		}
		return response{OK: true}
	default:
		return failure(errors.New("unknown lab command"))
	}
}
