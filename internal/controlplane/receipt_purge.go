package controlplane

import "context"

// PurgeExpiredReceipts deletes at most limit expired idempotency receipts from
// each receipt table and returns the number removed. Receipts hold encrypted
// responses, some of which carry issued tokens, so they must not outlive the
// documented 24 hour replay window. The receipt key row is never touched, so
// the key-binding guard of InitializeReceiptKey is unaffected.
func (s *Store) PurgeExpiredReceipts(ctx context.Context, limit int) (int64, error) {
	if limit < 1 || limit > 1000 {
		return 0, ErrInput
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return 0, err
	}
	defer rollback(tx)
	var total int64
	for _, table := range []string{"http_receipts", "tenant_http_receipts"} {
		// Constant table names only. SKIP LOCKED leaves a receipt that a
		// concurrent replay is reading to the next pass.
		tag, err := tx.Exec(ctx, `DELETE FROM `+table+` WHERE ctid IN
            (SELECT ctid FROM `+table+` WHERE expires_at<=clock_timestamp() ORDER BY expires_at LIMIT $1 FOR UPDATE SKIP LOCKED)`, limit)
		if err != nil {
			return 0, err
		}
		total += tag.RowsAffected()
	}
	return total, commit(ctx, tx)
}
