package consensus

import (
	"testing"
	"time"
)

func TestPrimaryArbiter(t *testing.T) {
	a := NewPrimaryArbiter(time.Minute, nil)
	base := time.Unix(1000, 0)
	a.now = func() time.Time { return base }

	if !a.Acquire("nodeA", 1) {
		t.Fatal("first node should become primary")
	}
	if a.Primary() != "nodeA" {
		t.Fatalf("primary = %q, want nodeA", a.Primary())
	}
	if !a.Acquire("nodeA", 1) {
		t.Fatal("primary should always re-acquire")
	}
	if a.Acquire("nodeB", 1) {
		t.Fatal("non-primary refused while primary is fresh")
	}

	// Within the timeout, still refused.
	a.now = func() time.Time { return base.Add(30 * time.Second) }
	if a.Acquire("nodeB", 1) {
		t.Fatal("non-primary refused within timeout")
	}
	// Primary keeps signing -> refreshes the idle timer.
	if !a.Acquire("nodeA", 1) {
		t.Fatal("primary re-acquire")
	}

	// Primary idle past the timeout -> nodeB takes over.
	a.now = func() time.Time { return base.Add(30*time.Second + time.Minute + time.Second) }
	if !a.Acquire("nodeB", 1) {
		t.Fatal("non-primary should take over after primary idle past timeout")
	}
	if a.Primary() != "nodeB" {
		t.Fatalf("primary = %q, want nodeB after failover", a.Primary())
	}
	if a.Acquire("nodeA", 1) {
		t.Fatal("old primary refused while new primary is fresh")
	}
}

// TestPrimaryArbiterPrefersFirstTarget covers the deployment shape this exists
// for: a co-located node listed first and a remote standby second. The standby
// only signs while the preferred node is away, and hands the role straight back
// when it returns.
func TestPrimaryArbiterPrefersFirstTarget(t *testing.T) {
	const (
		preferred = "10.0.0.1:26659" // co-located node, listed first
		standby   = "10.0.0.2:26659" // remote standby
	)
	a := NewPreferringPrimaryArbiter(time.Minute, []string{preferred, standby}, nil)
	base := time.Unix(1000, 0)
	a.now = func() time.Time { return base }

	if !a.Acquire(preferred, 1) {
		t.Fatal("preferred node should become primary")
	}
	if a.Acquire(standby, 1) {
		t.Fatal("standby must not preempt the preferred node")
	}

	// Preferred node's link drops; after the idle timeout the standby takes over.
	a.now = func() time.Time { return base.Add(time.Minute + time.Second) }
	if !a.Acquire(standby, 1) {
		t.Fatal("standby should take over once the preferred node is idle")
	}
	if a.Primary() != standby {
		t.Fatalf("primary = %q, want %q", a.Primary(), standby)
	}

	// Preferred node returns and reclaims immediately, without waiting for the
	// standby to go idle.
	a.now = func() time.Time { return base.Add(time.Minute + 2*time.Second) }
	if !a.Acquire(preferred, 1) {
		t.Fatal("preferred node should fail back as soon as it requests again")
	}
	if a.Primary() != preferred {
		t.Fatalf("primary = %q, want %q after failback", a.Primary(), preferred)
	}
	if a.Acquire(standby, 1) {
		t.Fatal("standby must be refused again once the preferred node is back")
	}
}

// TestPrimaryArbiterUnlistedRanksLast ensures a target missing from the
// preference list never preempts a listed one, and cannot be preempted by
// rank alone once it holds the role legitimately.
func TestPrimaryArbiterUnlistedRanksLast(t *testing.T) {
	a := NewPreferringPrimaryArbiter(time.Minute, []string{"listed"}, nil)
	base := time.Unix(1000, 0)
	a.now = func() time.Time { return base }

	if !a.Acquire("unlisted", 1) {
		t.Fatal("first requester becomes primary regardless of ranking")
	}
	if !a.Acquire("listed", 1) {
		t.Fatal("listed node outranks an unlisted primary")
	}
	if a.Acquire("unlisted", 1) {
		t.Fatal("unlisted node must not preempt a listed primary")
	}
}

// TestPrimaryArbiterWithoutPreferenceKeepsRole documents that the default
// constructor is unchanged: without a preference order the node that took over
// keeps signing until it goes idle.
func TestPrimaryArbiterWithoutPreferenceKeepsRole(t *testing.T) {
	a := NewPrimaryArbiter(time.Minute, nil)
	base := time.Unix(1000, 0)
	a.now = func() time.Time { return base }

	if !a.Acquire("nodeA", 1) {
		t.Fatal("first node should become primary")
	}
	a.now = func() time.Time { return base.Add(time.Minute + time.Second) }
	if !a.Acquire("nodeB", 1) {
		t.Fatal("nodeB takes over after idle timeout")
	}
	// nodeA is not preferred over nodeB, so it must wait for another idle window.
	if a.Acquire("nodeA", 1) {
		t.Fatal("without a preference order there is no fail-back")
	}
}

func TestPrimaryArbiterReleaseAllowsImmediateFailover(t *testing.T) {
	a := NewPrimaryArbiter(time.Minute, nil)
	base := time.Unix(1000, 0)
	a.now = func() time.Time { return base }

	switch {
	case !a.Acquire("nodeA", 1):
		t.Fatal("first node should become primary")
	case a.Release("nodeB"):
		t.Fatal("non-primary release should have no effect")
	case a.Primary() != "nodeA":
		t.Fatalf("primary = %q after stale release, want nodeA", a.Primary())
	case !a.Release("nodeA"):
		t.Fatal("primary release should succeed")
	case a.Primary() != "":
		t.Fatalf("primary = %q after release, want empty", a.Primary())
	case !a.Acquire("nodeB", 1):
		t.Fatal("standby should take over immediately after primary release")
	case a.Primary() != "nodeB":
		t.Fatalf("primary = %q after failover, want nodeB", a.Primary())
	}
}

// TestAcquireDefersFailBackWhileBehind covers the failure seen in production on
// 2026-09-09: the preferred node stalled, the standby took over and signed ahead,
// and the moment the preferred node came back it reclaimed the role while still
// behind. Every request it then made was refused as a height regression, costing
// exactly those blocks. Fail-back must wait until it has caught up.
func TestAcquireDefersFailBackWhileBehind(t *testing.T) {
	a := NewPreferringPrimaryArbiter(time.Second, []string{"preferred", "standby"}, nil)

	// The preferred node is elected and signs up to height 100.
	if !a.Acquire("preferred", 100) {
		t.Fatal("preferred node should be elected first")
	}

	// It stalls; after the idle timeout the standby takes over and signs ahead.
	a.now = func() time.Time { return time.Now().Add(2 * time.Second) }
	if !a.Acquire("standby", 110) {
		t.Fatal("standby should take over after the idle timeout")
	}

	// The preferred node returns, but behind what has already been signed. It must
	// not reclaim the role yet, and the standby must stay primary.
	if a.Acquire("preferred", 105) {
		t.Fatal("preferred node must not fail back while behind the signed height")
	}
	if got := a.Primary(); got != "standby" {
		t.Fatalf("primary = %q, want standby while the preferred node is behind", got)
	}

	// Once caught up past the signed height it reclaims the role.
	if !a.Acquire("preferred", 111) {
		t.Fatal("preferred node should fail back once caught up")
	}
	if got := a.Primary(); got != "preferred" {
		t.Fatalf("primary = %q, want preferred after catching up", got)
	}
}
