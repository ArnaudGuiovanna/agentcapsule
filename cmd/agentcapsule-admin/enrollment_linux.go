package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/operatorconfig"
)

func issueEnrollment(args []string) int {
	f := flag.NewFlagSet("issue-enrollment", flag.ContinueOnError)
	account := f.String("platform-account", "", "individual operator name")
	path := f.String("token-file", "", "private one-time enrollment file")
	ttl := f.Duration("lifetime", 15*time.Minute, "validity (1m to 1h)")
	if f.Parse(args) != nil || f.NArg() != 0 || *account == "" || *path == "" {
		return 2
	}
	fail := func(msg string) int { fmt.Fprintln(os.Stderr, msg); return 1 }
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, code := openOperatorStore(ctx, fail)
	if s == nil {
		return code
	}
	defer s.Close()
	proof, err := operatorconfig.EnsurePrivate(*path, 48, func() []byte {
		var b [32]byte
		rand.Read(b[:])
		return []byte("acpe_" + base64.RawURLEncoding.EncodeToString(b[:]))
	})
	if err != nil {
		return fail("enrollment_file_invalid")
	}
	if err = s.IssuePlatformEnrollment(operator(ctx), *account, string(proof), *ttl); err != nil {
		return fail("enrollment_not_issued")
	}
	fmt.Fprintln(os.Stdout, "enrollment_ready")
	return 0
}
