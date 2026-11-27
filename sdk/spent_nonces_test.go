package sdk

import (
	"fmt"
	"testing"
	"time"
)

// TestSpentNoncesNeverForgetEarly fills the set and checks that a spent
// nonce stays spent until it expires, that new nonces are refused rather
// than evicting old ones, and that expired ones make room.
func TestSpentNoncesNeverForgetEarly(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	nonces := newSpentNonces(3)
	for index := range 3 {
		if !nonces.spend(fmt.Sprint(index), now.Add(time.Minute), now) {
			t.Fatalf("nonce %d was refused with room left", index)
		}
	}
	if nonces.spend("0", now.Add(time.Minute), now) {
		t.Fatal("a spent nonce was spent again")
	}
	if nonces.spend("3", now.Add(time.Minute), now) {
		t.Fatal("a new nonce evicted an unexpired one")
	}
	if nonces.spend("0", now.Add(time.Minute), now.Add(30*time.Second)) {
		t.Fatal("a spent nonce was forgotten before it expired")
	}
	later := now.Add(2 * time.Minute)
	if !nonces.spend("3", later.Add(time.Minute), later) {
		t.Fatal("expired nonces made no room")
	}
}
