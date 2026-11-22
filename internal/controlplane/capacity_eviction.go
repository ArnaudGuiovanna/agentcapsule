package controlplane

import "context"

// EvictableForWork returns, in eviction order, those of the running agents
// that work may stop now: none that is computing (ADR 017 §2.1). A worker
// asks again once it holds a victim's turn, since the victim may have started
// computing while the worker waited for the calls already admitted on it.
func (s *Store) EvictableForWork(ctx context.Context, running []string) ([]string, error) {
	if len(running) == 0 {
		return nil, nil
	}
	tx, err := s.begin(ctx)
	if err != nil {
		return nil, err
	}
	defer rollback(tx)
	order, err := evictionOrder(ctx, tx, running, true)
	if err != nil {
		return nil, err
	}
	return order, commit(ctx, tx)
}
