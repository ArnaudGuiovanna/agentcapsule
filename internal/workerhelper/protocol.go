// Package workerhelper is the boundary between the worker, which runs as an
// account with no capability, and its root helper (ADR 024). The helper
// does the host operations that need root, about the worker's own VMs and
// files only: it gives a volume or a build drive to its VM's UID, builds a
// VM's jail and cgroup, starts the jailer, observes and cleans up a run,
// connects to or listens on a VM's sockets, runs a confined program as the
// inspection UID, and fetches an archive.
//
// A request names identifiers (an agent, a run, a volume), never a UID to
// switch to, a program to run as root, a cgroup or a jail path: the helper
// derives those from the worker's registry and the root-owned worker
// configuration, and refuses what does not match. The transport is a
// SOCK_SEQPACKET Unix socket: one JSON object of at most MaxMessage bytes and
// at most MaxFiles descriptors per message, authenticated by SO_PEERCRED both
// ways. This package imports no other package of this repository but
// internal/sandbox, so that the helper binary stays small.
package workerhelper

import (
	"errors"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/sandbox"
)

// Version is the protocol's version: every request carries it.
const Version = 1

const (
	// MaxMessage bounds one message's JSON.
	MaxMessage = 64 << 10
	// MaxFiles bounds the descriptors one message carries.
	MaxFiles = 4
	// MaxConfig bounds a VM's config.json.
	MaxConfig = 32 << 10
	// MaxAppendix bounds the files a boot appends to its initrd.
	MaxAppendix = 1 << 20
	// MaxRegistry bounds the worker's registry.json.
	MaxRegistry = 16 << 20
)

// The operations of version 1 (ADR 024 §3).
const (
	OpHello         = "hello"
	OpGiveVolume    = "give_volume"
	OpOpenVolume    = "open_volume"
	OpGiveDrives    = "give_drives"
	OpReclaimDrives = "reclaim_drives"
	OpCheckLinkable = "check_linkable"
	OpPrepare       = "prepare"
	OpStart         = "start"
	OpObserve       = "observe"
	OpPopulated     = "populated"
	OpCleanup       = "cleanup"
	OpDial          = "dial"
	OpListen        = "listen"
	OpSandbox       = "sandbox"
	OpFetchArchive  = "fetch_archive"
)

// Request is one request of the worker.
type Request struct {
	V     int    `json:"v"`
	Op    string `json:"op"`
	Agent string `json:"agent,omitempty"`
	Run   string `json:"run,omitempty"`
	// Path is a volume (give_volume, open_volume), an image (sandbox) or an
	// archive root (fetch_archive).
	Path  string   `json:"path,omitempty"`
	Paths []string `json:"paths,omitempty"`
	// Drives are the build drives give_drives gives the agent's UID.
	Drives []Drive `json:"drives,omitempty"`
	UID    uint32  `json:"uid,omitempty"`
	Write  bool    `json:"write,omitempty"`
	Lock   bool    `json:"lock,omitempty"`
	// Config is the VM's config.json (prepare).
	Config  []byte          `json:"config,omitempty"`
	Sandbox *SandboxRequest `json:"sandbox,omitempty"`
	Store   string          `json:"store,omitempty"`
	Archive string          `json:"archive,omitempty"`
}

// Drive is a build drive and the mode it gets: 0400 or 0600.
type Drive struct {
	Path string `json:"path"`
	Mode uint32 `json:"mode"`
}

// SandboxRequest is a confined run: Program, an absolute path, or Self, the
// name of a program of the worker's executable (sandbox.RunSelf).
type SandboxRequest struct {
	Program   string   `json:"program,omitempty"`
	Self      string   `json:"self,omitempty"`
	Args      []string `json:"args,omitempty"`
	Input     []byte   `json:"input,omitempty"`
	TimeoutMS int64    `json:"timeout_ms,omitempty"`
	CPUMS     int64    `json:"cpu_ms,omitempty"`
}

// Response is the helper's answer.
type Response struct {
	OK    bool   `json:"ok"`
	Code  string `json:"code,omitempty"`
	Error string `json:"error,omitempty"`
	// hello
	Version int    `json:"version,omitempty"`
	Jails   string `json:"jails,omitempty"`
	Cgroup  string `json:"cgroup,omitempty"`
	// observe
	Observation *Observation `json:"observation,omitempty"`
	// populated
	Populated bool `json:"populated,omitempty"`
	// sandbox
	Output []byte `json:"output,omitempty"`
}

// Observation is what observe found of a run's VMM: its PID and start time,
// and whether it has the agent's volume open and holds its lock. LockError
// is a failure to read its descriptors once identified.
type Observation struct {
	PID       int    `json:"pid"`
	Ticks     string `json:"ticks"`
	Open      bool   `json:"open,omitempty"`
	Locked    bool   `json:"locked,omitempty"`
	LockError string `json:"lock_error,omitempty"`
}

// The closed codes of a refused or failed request.
const (
	CodeInvalid      = "invalid"
	CodeRefused      = "refused"
	CodeUnknownAgent = "unknown_agent"
	CodeAbsent       = "absent"
	CodeBusy         = "busy"
	CodeFailed       = "failed"
	CodeUnavailable  = "unavailable"
	CodeLimit        = "limit"
	CodeSyscall      = "syscall"
	CodeUnsupported  = "unsupported"
	CodeCrossDevice  = "cross_device"
)

var (
	// ErrHelperUnavailable: the helper did not answer. It never means that a
	// VMM is gone or that a file is absent.
	ErrHelperUnavailable = errors.New("the worker helper does not answer")
	ErrInvalid           = errors.New("worker helper: invalid request")
	ErrRefused           = errors.New("worker helper: request refused")
	ErrUnknownAgent      = errors.New("worker helper: agent not in the registry")
	// ErrAbsent: no VMM of the run could be identified.
	ErrAbsent      = errors.New("worker helper: no identified VMM")
	ErrBusy        = errors.New("worker helper: busy")
	ErrFailed      = errors.New("worker helper: operation failed")
	ErrUnsupported = errors.New("worker helper: unsupported version or operation")
	// ErrCrossDevice: a file a jail must share by hard link is on another
	// file system or mount than the jails. It is never copied (ADR 023 §5.1).
	ErrCrossDevice = errors.New("worker helper: a corpus image or a build drive is outside the jails' file system: it is never copied")
)

var codeErrors = map[string]error{
	CodeInvalid: ErrInvalid, CodeRefused: ErrRefused, CodeUnknownAgent: ErrUnknownAgent, CodeAbsent: ErrAbsent,
	CodeBusy: ErrBusy, CodeFailed: ErrFailed, CodeUnavailable: sandbox.ErrUnavailable, CodeLimit: sandbox.ErrLimit,
	CodeSyscall: sandbox.ErrSyscall, CodeUnsupported: ErrUnsupported, CodeCrossDevice: ErrCrossDevice,
}

// Error is a refusal or a failure the helper answered.
type Error struct {
	Code, Message string
}

func (e *Error) Error() string {
	if e.Message == "" {
		return "worker helper: " + e.Code
	}
	return "worker helper: " + e.Code + ": " + e.Message
}

// Unwrap gives the code's sentinel: ErrRefused, ErrAbsent, sandbox.ErrLimit...
func (e *Error) Unwrap() error {
	if err, ok := codeErrors[e.Code]; ok {
		return err
	}
	return ErrFailed
}

// codeOf is the closed code of an error the server met.
func codeOf(err error) string {
	for code, sentinel := range codeErrors {
		if errors.Is(err, sentinel) {
			return code
		}
	}
	return CodeFailed
}

// refuse is a refusal with a short reason, which never holds file contents.
func refuse(reason string) error { return &Error{Code: CodeRefused, Message: reason} }

func invalid(reason string) error { return &Error{Code: CodeInvalid, Message: reason} }
