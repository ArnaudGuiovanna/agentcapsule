package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const watchIdle = 45 * time.Second

var watchID = regexp.MustCompile(`^[0-9]{1,9}:[0-9]{1,18}$`)

// A socket can split a single event across reads. Each received byte keeps the
// connection alive, including the comments between events.
type idleReader struct {
	io.Reader
	timer *time.Timer
}

func (r idleReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if n > 0 {
		r.timer.Reset(watchIdle)
	}
	return n, err
}

type watchEvent struct {
	name, id string
	data     []byte
}

func (e watchEvent) emit(w io.Writer, textOnly bool) (bool, error) {
	if len(e.data) == 0 || e.data[0] != '{' || !json.Valid(e.data) {
		return false, errors.New("invalid invocation event data")
	}
	if e.id != "" && !watchID.MatchString(e.id) {
		return false, errors.New("invalid invocation event ID")
	}
	if textOnly {
		if e.name == "delta" {
			var d struct {
				Text string `json:"text"`
			}
			if err := json.Unmarshal(e.data, &d); err != nil {
				return false, err
			}
			if _, err := io.WriteString(w, d.Text); err != nil {
				return false, err
			}
		}
	} else {
		evt := struct {
			Version int             `json:"version"`
			Event   string          `json:"event"`
			Data    json.RawMessage `json:"data"`
		}{1, e.name, e.data}
		if err := json.NewEncoder(w).Encode(evt); err != nil {
			return false, err
		}
	}
	switch e.name {
	case "revoked":
		return true, terminalFailure{"revoked"}
	case "end":
		state, disposition, err := operationState(e.data)
		if err != nil {
			return true, err
		}
		if disposition == "failure" {
			return true, terminalFailure{state}
		}
		if disposition != "success" {
			return true, errors.New("unexpected invocation end state")
		}
		return true, nil
	}
	return false, nil
}

// consumeWatch advances the cursor only after a complete, delivered event.
// A partial final event is replayed upon reconnection.
func consumeWatch(src io.Reader, w io.Writer, textOnly bool, last *string) (reconnect bool, err error) {
	r := bufio.NewReaderSize(src, 128<<10)
	var e watchEvent
	for {
		line, err := r.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			return false, errors.New("invocation event exceeds its size limit")
		}
		if err != nil {
			return true, err
		}
		line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte{'\n'}), []byte{'\r'})
		if len(line) == 0 {
			if e.name != "" {
				done, err := e.emit(w, textOnly)
				if done || err != nil {
					return false, err
				}
				if e.id != "" {
					*last = e.id
				}
			}
			e = watchEvent{}
			continue
		}
		k, v, ok := bytes.Cut(line, []byte{':'})
		if !ok {
			continue
		}
		v = bytes.TrimPrefix(v, []byte{' '})
		switch string(k) {
		case "event":
			e.name = string(v)
		case "id":
			e.id = string(v)
		case "data":
			if e.data != nil {
				return false, errors.New("expected one data line per invocation event")
			}
			e.data = bytes.Clone(v)
		}
	}
}

func (cli console) watchInvocation(ctx context.Context, c *client, route string, textOnly bool) error {
	if !validRoute(route) {
		return errors.New("invalid invocation events route")
	}
	stream := &http.Client{Transport: c.http.Transport, CheckRedirect: c.http.CheckRedirect, Jar: c.http.Jar}
	last := ""
	established := false
	for {
		token := c.connection.Token
		if c.connection.SigningKey != "" {
			var err error
			token, err = signPersonal(c.connection.SigningKey, c.connection.Organization)
			if err != nil {
				return err
			}
		}
		attempt, cancel := context.WithCancel(ctx)
		timer := time.AfterFunc(watchIdle, cancel)
		req, err := http.NewRequestWithContext(attempt, http.MethodGet, strings.TrimRight(c.connection.URL, "/")+route, nil)
		if err != nil {
			timer.Stop()
			cancel()
			return err
		}
		req.Header.Set("Accept", "text/event-stream")
		req.Header.Set("Authorization", "Bearer "+token)
		if last != "" {
			req.Header.Set("Last-Event-ID", last)
		}
		res, err := stream.Do(req)
		reconnect := established
		if err == nil {
			if res.StatusCode != http.StatusOK {
				err = responseError(res, safeCode(res.Header.Get("X-Request-ID")))
				reconnect = false
			} else if typ, _, parseErr := mime.ParseMediaType(res.Header.Get("Content-Type")); parseErr != nil || typ != "text/event-stream" {
				err = errors.New("expected an invocation event stream")
				reconnect = false
			} else {
				established = true
				timer.Reset(watchIdle)
				reconnect, err = consumeWatch(idleReader{res.Body, timer}, cli.out, textOnly, &last)
			}
			res.Body.Close()
		} else if !established && ctx.Err() == nil {
			err = fmt.Errorf("opening invocation event stream: %w", err)
		}
		timer.Stop()
		cancel()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !reconnect {
			return err
		}
		if err = wait(ctx, time.Second); err != nil {
			return err
		}
	}
}
