package sdk

import (
	"context"
	"sync"
	"time"
)

// SpentNonceStore records the terminal sign-in nonces already exchanged, so
// each sign-in is exchanged once. Spend reports whether nonce was unspent and,
// if so, records it as spent until expires. It must be atomic across every
// process serving the instance: of two calls with one nonce, exactly one
// reports true. An error refuses the sign-in.
type SpentNonceStore interface {
	Spend(ctx context.Context, nonce string, expires time.Time) (bool, error)
}

var _ SpentNonceStore = (*spentNonces)(nil)

// spentNonces is the default SpentNonceStore, in this process's memory. It
// remembers each terminal authentication nonce until its transaction expires, so an unexpired state cannot be exchanged twice. It
// never forgets a nonce early: when it holds its maximum of unexpired nonces,
// it refuses new ones instead of evicting old ones.
//
// It is per process. Replicas of one instance, or a restart within a
// transaction's lifetime, do not share it.
type spentNonces struct {
	mutex   sync.Mutex
	maximum int
	expires map[string]time.Time
}

func newSpentNonces(maximum int) *spentNonces {
	return &spentNonces{maximum: maximum, expires: map[string]time.Time{}}
}

// Spend records nonce as spent until expires and reports whether it was
// unspent and there was room to remember it.
func (s *spentNonces) Spend(_ context.Context, nonce string, expires time.Time) (bool, error) {
	return s.spend(nonce, expires, time.Now()), nil
}

// spend is Spend at now.
func (s *spentNonces) spend(nonce string, expires time.Time, now time.Time) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if spentUntil, spent := s.expires[nonce]; spent && now.Before(spentUntil) {
		return false
	}
	if len(s.expires) >= s.maximum {
		for spentNonce, spentUntil := range s.expires {
			if !now.Before(spentUntil) {
				delete(s.expires, spentNonce)
			}
		}
		if len(s.expires) >= s.maximum {
			return false
		}
	}
	s.expires[nonce] = expires
	return true
}
