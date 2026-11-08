//go:build linux && amd64

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/ArnaudGuiovanna/agentcapsule/internal/capsuleprotocol"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/harnessstore"
)

// This fixture demonstrates a durable local outbox: the control handler only
// inserts SQL intent. The platform RPC happens AFTER that transaction commits.
// Retrying an ambiguous platform commit reuses the same business idempotency key.
type platformCommand struct {
	Op         string                     `json:"fixture_op"`
	Key        string                     `json:"key"`
	JobID      string                     `json:"job_id"`
	RequestID  string                     `json:"request_id"`
	Submission capsuleprotocol.Submission `json:"submission"`
	Reply      capsuleprotocol.Reply      `json:"reply"`
	Candidates []string                   `json:"candidates"`
}
type platformResult struct {
	Done    bool                             `json:"done"`
	Receipt *capsuleprotocol.PlatformReceipt `json:"receipt,omitempty"`
	Agents  []string                         `json:"agents,omitempty"`
	Code    string                           `json:"code,omitempty"`
}

func platformIntent(ctx context.Context, e harnessstore.Event, tx harnessstore.SQL) (bool, []byte, error) {
	var command platformCommand
	if json.Unmarshal(e.Body, &command) != nil || command.Op == "" {
		return false, nil, nil
	}
	if command.Op == "platform_result" {
		var b []byte
		err := tx.QueryRowContext(ctx, "SELECT result FROM platform_jobs WHERE id=?", command.JobID).Scan(&b)
		if errors.Is(err, sql.ErrNoRows) || err == nil && b == nil {
			return true, []byte(`{"done":false}`), nil
		}
		return true, b, err
	}
	switch command.Op {
	case "platform_submit", "platform_reply", "platform_search", "platform_health":
	default:
		return true, nil, errors.New("unknown fixture command")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO platform_jobs(id,command) VALUES (?,?)", e.ID, e.Body); err != nil {
		return true, nil, err
	}
	return true, []byte(`{"queued":true}`), nil
}

func startPlatformJobs(credentials *capsuleprotocol.Credentials) {
	db, err := sql.Open("sqlite3", "file:/data/harness.db?_journal_mode=WAL&_synchronous=FULL&_busy_timeout=5000")
	must(err)
	_, err = db.Exec("CREATE TABLE IF NOT EXISTS platform_jobs (id TEXT PRIMARY KEY,command BLOB NOT NULL,result BLOB)")
	must(err)
	if credentials == nil {
		db.Close()
		return
	} // barrier-only boot has no platform key
	client, err := capsuleprotocol.NewPlatformClient(*credentials, capsuleprotocol.DialPlatform)
	must(err)
	go func() {
		for {
			var id string
			var b []byte
			err := db.QueryRow("SELECT id,command FROM platform_jobs WHERE result IS NULL ORDER BY rowid LIMIT 1").Scan(&id, &b)
			if err != nil {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			var command platformCommand
			if json.Unmarshal(b, &command) != nil {
				time.Sleep(20 * time.Millisecond)
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			result := platformResult{Done: true}
			var receipt capsuleprotocol.PlatformReceipt
			switch command.Op {
			case "platform_submit":
				receipt, err = client.Submit(ctx, command.Key, command.Submission)
				if err == nil {
					result.Receipt = &receipt
				}
			case "platform_reply":
				receipt, err = client.Reply(ctx, command.RequestID, command.Key, command.Reply)
				if err == nil {
					result.Receipt = &receipt
				}
			case "platform_search":
				result.Agents, err = client.Search(ctx, command.Candidates)
			case "platform_health":
				err = client.Health(ctx)
			default:
				err = errors.New("invalid fixture job")
			}
			cancel()
			var remote *capsuleprotocol.PlatformError
			if errors.Is(err, capsuleprotocol.ErrTransport) || errors.As(err, &remote) && (remote.Code == "unavailable" || remote.Code == "commit_unknown") {
				time.Sleep(40 * time.Millisecond)
				continue
			}
			if err != nil {
				result.Code = "protocol_error"
				if remote != nil {
					result.Code = remote.Code
				}
			}
			encoded, err := json.Marshal(result)
			if err != nil {
				continue
			}
			// Failure to record a completed job safely retries its remote key.
			_, _ = db.Exec("UPDATE platform_jobs SET result=? WHERE id=? AND result IS NULL", encoded, id)
		}
	}()
}
