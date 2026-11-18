//go:build linux && cgo

package authorityclient

import (
	"context"
	"errors"
	"io"
	"time"

	svc "github.com/ArnaudGuiovanna/agentcapsule/internal/authorityservice"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/controlplane"
	"github.com/ArnaudGuiovanna/agentcapsule/internal/keyauthority"
)

// ReceiptKey asks the service for the daily receipt key of day
// (docs/adr/006-authority-service.md §7): 32 bytes, in a buffer the caller
// owns and clears. The service gives yesterday's, today's and tomorrow's,
// by its clock, and creates today's if it is missing. A day whose key is
// gone, destroyed or never held there, is keyauthority.ErrRevoked; a day
// out of range keyauthority.ErrInput.
func (a *API) ReceiptKey(ctx context.Context, day time.Time) ([]byte, error) {
	return a.c.receiptKey(ctx, day)
}

// ReceiptKeys is the API's source of daily receipt keys, in the control
// plane's terms: a day whose key is gone is controlplane.ErrReceiptKeyGone.
func (a *API) ReceiptKeys() controlplane.ReceiptKeySource {
	return func(ctx context.Context, day time.Time) ([]byte, error) {
		key, err := a.ReceiptKey(ctx, day)
		if errors.Is(err, keyauthority.ErrRevoked) {
			return nil, errors.Join(controlplane.ErrReceiptKeyGone, err)
		}
		return key, err
	}
}

// receiptKey runs receipt_key: its answer is a frame, then the key's raw
// bytes, read into a buffer this client owns; never JSON.
func (c *Client) receiptKey(ctx context.Context, day time.Time) ([]byte, error) {
	name := keyauthority.ReceiptDay(day).Format(time.DateOnly)
	conn, deadline, err := c.send(ctx, svc.OpReceiptKey, svc.ReceiptKeyArgs{Day: name})
	if err != nil {
		return nil, err
	}
	r, err := receive(ctx, conn, deadline.Add(grace))
	if err != nil {
		conn.Close()
		return nil, outage(ctx, err)
	}
	var result svc.ReceiptKeyResult
	switch {
	case r.Error != "":
		if closes(r.Error) {
			conn.Close()
		} else {
			c.put(conn)
		}
		return nil, withContext(ctx, svc.ErrorOf(r.Error))
	case r.Held != nil || strictJSON(r.Result, &result) != nil || result.Day != name:
		conn.Close()
		return nil, svc.ErrorOf(svc.CodeProtocol)
	}
	key := make([]byte, svc.KeySize)
	conn.SetReadDeadline(deadline.Add(grace))
	if _, err = io.ReadFull(conn, key); err != nil {
		clear(key)
		conn.Close()
		return nil, outage(ctx, err)
	}
	conn.SetReadDeadline(time.Time{})
	c.put(conn)
	return key, nil
}
