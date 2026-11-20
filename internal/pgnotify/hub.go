// Package pgnotify wakes a process's subscribers on PostgreSQL notifications
// (ADR 022 §6.5). One dedicated connection, outside the pool, listens on the
// channels named at start; a subscriber registers under a channel and a
// payload, and is woken at each notification of both. A wake carries
// nothing: the subscriber reads its state with a short query on the pool.
//
// Without the connection, every subscriber is woken every second until the
// hub has connected again (backoff from 1 to 30 seconds), and once more then:
// nothing notified meanwhile is missed. Payloads are opaque identifiers,
// never content.
package pgnotify

import (
	"context"
	"errors"
	"regexp"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Hub wakes subscribers on notifications.
type Hub interface {
	// Subscribe wakes c (buffered, one slot; a wake is never lost, only
	// merged) at each notification of channel with this payload, and every
	// second while the hub has no connection. cancel ends the subscription.
	Subscribe(channel, payload string) (c <-chan struct{}, cancel func())
}

// ErrInput: an invalid channel name, or no channel.
var ErrInput = errors.New("invalid notification channel")

var channelName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

const (
	// pollInterval wakes every subscriber while the hub has no connection.
	pollInterval = time.Second
	minBackoff   = time.Second
	maxBackoff   = 30 * time.Second
	// probeInterval: a connection silent that long is checked with a ping.
	probeInterval = 30 * time.Second
)

type key struct{ channel, payload string }

// Listener is the hub of one process.
type Listener struct {
	connect  func(context.Context) (*pgx.Conn, error)
	channels []string

	mu        sync.Mutex
	subs      map[key]map[chan struct{}]struct{}
	connected bool
}

var _ Hub = (*Listener)(nil)

// New returns a hub that listens on channels through connections that
// connect opens. Run starts it.
func New(connect func(context.Context) (*pgx.Conn, error), channels ...string) (*Listener, error) {
	if connect == nil || len(channels) == 0 {
		return nil, ErrInput
	}
	for _, c := range channels {
		if !channelName.MatchString(c) {
			return nil, ErrInput
		}
	}
	return &Listener{connect: connect, channels: channels, subs: map[key]map[chan struct{}]struct{}{}}, nil
}

// Subscribe registers a subscriber. It works before Run and while the hub
// has no connection: the subscriber is then polled.
func (l *Listener) Subscribe(channel, payload string) (<-chan struct{}, func()) {
	c := make(chan struct{}, 1)
	k := key{channel, payload}
	l.mu.Lock()
	if l.subs[k] == nil {
		l.subs[k] = map[chan struct{}]struct{}{}
	}
	l.subs[k][c] = struct{}{}
	l.mu.Unlock()
	var once sync.Once
	return c, func() {
		once.Do(func() {
			l.mu.Lock()
			delete(l.subs[k], c)
			if len(l.subs[k]) == 0 {
				delete(l.subs, k)
			}
			l.mu.Unlock()
		})
	}
}

// Connected reports whether the hub listens now.
func (l *Listener) Connected() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.connected
}

func notify(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

func (l *Listener) wake(k key) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for c := range l.subs[k] {
		notify(c)
	}
}

func (l *Listener) wakeAll() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, subs := range l.subs {
		for c := range subs {
			notify(c)
		}
	}
}

func (l *Listener) setConnected(v bool) {
	l.mu.Lock()
	l.connected = v
	l.mu.Unlock()
	// Once connected, each subscriber reads once: what was notified before
	// the LISTEN, or while the hub had no connection, is not missed.
	l.wakeAll()
}

// Run listens until ctx ends, connecting again after each failure. It
// returns ctx's error.
func (l *Listener) Run(ctx context.Context) error {
	poll := time.NewTicker(pollInterval)
	defer poll.Stop()
	polled := make(chan struct{})
	go func() {
		defer close(polled)
		for {
			select {
			case <-ctx.Done():
				return
			case <-poll.C:
				if !l.Connected() {
					l.wakeAll()
				}
			}
		}
	}()
	defer func() { <-polled }()
	backoff := minBackoff
	for ctx.Err() == nil {
		if err := l.session(ctx); err == nil {
			backoff = minBackoff
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(2*backoff, maxBackoff)
	}
	return ctx.Err()
}

// session holds one connection until it fails; nil if it listened at all.
func (l *Listener) session(ctx context.Context) error {
	conn, err := l.connect(ctx)
	if err != nil {
		return err
	}
	defer func() {
		closing, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = conn.Close(closing)
		cancel()
	}()
	for _, c := range l.channels {
		if _, err = conn.Exec(ctx, "LISTEN "+pgx.Identifier{c}.Sanitize()); err != nil {
			return err
		}
	}
	l.setConnected(true)
	defer l.setConnected(false)
	for {
		wait, cancel := context.WithTimeout(ctx, probeInterval)
		n, err := conn.WaitForNotification(wait)
		silent := errors.Is(wait.Err(), context.DeadlineExceeded)
		cancel()
		switch {
		case err == nil:
			l.wake(key{n.Channel, n.Payload})
		case ctx.Err() != nil:
			return nil
		case silent && !conn.IsClosed():
			// A timeout leaves the connection usable: check that it lives.
			probe, cancel := context.WithTimeout(ctx, 5*time.Second)
			err = conn.Ping(probe)
			cancel()
			if err != nil {
				return nil
			}
		default:
			return nil
		}
	}
}
