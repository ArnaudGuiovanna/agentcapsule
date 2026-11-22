package controlplane

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
)

// replayReceipt decrypts the authorized replay and applies current revocations
// before returning a stored credential. Scope and AAD come from its table.
func (a *Accounts) replayReceipt(ctx context.Context, tx pgx.Tx, status int, ciphertext []byte, day *time.Time, aad []byte, scope string) (APIReceipt, error) {
	plain, err := a.openReceipt(ctx, ciphertext, day, aad, scope)
	if err != nil {
		return APIReceipt{}, err
	}
	plain, err = currentRevocations(ctx, tx, plain)
	if err != nil {
		return APIReceipt{}, err
	}
	return APIReceipt{Status: status, Body: plain, Replayed: true}, nil
}

// makeReceipt obtains the encryption key before running the protected mutation.
// The caller inserts its ciphertext in the same transaction as the mutation.
func (a *Accounts) makeReceipt(ctx context.Context, fn func() (int, any, error), aad func(int) []byte) (APIReceipt, []byte, *time.Time, error) {
	sealer, day, err := a.receiptSealer(ctx)
	if err != nil {
		return APIReceipt{}, nil, nil, err
	}
	status, body, err := fn()
	if err != nil {
		return APIReceipt{}, nil, nil, err
	}
	plain, err := json.Marshal(body)
	if err != nil {
		return APIReceipt{}, nil, nil, err
	}
	nonce := make([]byte, sealer.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return APIReceipt{}, nil, nil, err
	}
	ciphertext := sealer.Seal(nonce, nonce, plain, aad(status))
	return APIReceipt{Status: status, Body: plain}, ciphertext, day, nil
}
