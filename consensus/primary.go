package consensus

import (
	"sync"
	"time"

	"github.com/cometbft/cometbft/libs/log"
)

// PrimaryArbiter enforces active-passive consensus signing across nodes that
// share one validator key. Each dial target (its address / IP) is an id; only
// the current "primary" id may have its vote/proposal requests signed. If the
// primary sends no sign request within the failover timeout, the next id to
// request takes over.
//
// When a preference order is configured the arbiter additionally fails back:
// the earliest listed id that is actively requesting always holds the role, so
// a preferred node reclaims it as soon as it is reachable again. Without a
// preference order the node that took over keeps the role until it goes idle.
//
// This stops two active nodes from racing the signer (which otherwise shows up
// as step-regression / conflicting-data rejections and the occasional missed
// block). The priv_validator_state high-water-mark check remains the ultimate
// double-sign backstop; this is an additional, earlier gate. Hand-over is safe
// at any moment because LockedPrivValidator serialises the two dial clients and
// the underlying FilePV refuses any height/round/step regression or conflicting
// data at the same step; the worst case is a single refused vote.
type PrimaryArbiter struct {
	timeout time.Duration
	logger  log.Logger

	// rank orders ids by preference, lower being preferred. Ids missing from
	// the map are unranked and rank behind every listed id. An empty map
	// disables the preference and leaves failover idle-based only.
	rank map[string]int

	mu      sync.Mutex
	primary string
	lastReq time.Time

	// maxHeight is the greatest height this arbiter has granted a sign request
	// for. A preferred node is only allowed to fail back once it has caught up
	// to it; otherwise it would reclaim the role while still behind and every
	// request until it catches up is refused as a height regression.
	maxHeight int64

	now func() time.Time // overridable in tests
}

// NewPrimaryArbiter returns an arbiter that fails over to another node after the
// primary has been idle for timeout. timeout must be > 0.
func NewPrimaryArbiter(timeout time.Duration, logger log.Logger) *PrimaryArbiter {
	return NewPreferringPrimaryArbiter(timeout, nil, logger)
}

// NewPreferringPrimaryArbiter returns an arbiter that keeps the idle-based
// failover of NewPrimaryArbiter and, in addition, always prefers the earliest
// id in preferOrder that is asking to sign. Passing a nil or empty preferOrder
// is identical to NewPrimaryArbiter. timeout must be > 0.
func NewPreferringPrimaryArbiter(timeout time.Duration, preferOrder []string, logger log.Logger) *PrimaryArbiter {
	if logger == nil {
		logger = log.NewNopLogger()
	}
	rank := make(map[string]int, len(preferOrder))
	for i, id := range preferOrder {
		if _, dup := rank[id]; dup {
			continue
		}
		rank[id] = i
	}
	return &PrimaryArbiter{timeout: timeout, rank: rank, logger: logger, now: time.Now}
}

// outranks reports whether id is preferred over the current primary. It is only
// meaningful while a.mu is held and a.primary is neither "" nor id.
func (a *PrimaryArbiter) outranks(id string) bool {
	if len(a.rank) == 0 {
		return false
	}
	mine, listed := a.rank[id]
	if !listed {
		return false
	}
	theirs, listed := a.rank[a.primary]
	if !listed {
		return true
	}
	return mine < theirs
}

// Acquire reports whether id may sign now. The current primary always may (and
// refreshes the idle timer); another id may take over when there is no primary
// yet, when the current primary has been idle longer than the timeout, or when
// it is preferred over the current primary.
func (a *PrimaryArbiter) Acquire(id string, height int64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	now := a.now()
	switch {
	case a.primary == id:
		a.lastReq = now
		a.grant(height)
		return true

	case a.primary == "":
		a.primary = id
		a.lastReq = now
		a.grant(height)
		a.logger.Info("consensus primary signer elected", "primary", id)
		return true

	case now.Sub(a.lastReq) > a.timeout:
		prev := a.primary
		a.primary = id
		a.lastReq = now
		a.grant(height)
		a.logger.Info("consensus primary signer failed over", "from", prev, "to", id, "after_idle", a.timeout.String())
		return true

	// Fail back only once the preferred node has caught up. Taking the role back
	// while it is behind means every request until it catches up is refused by the
	// height-regression check, which costs exactly those blocks.
	case a.outranks(id) && height < a.maxHeight:
		a.logger.Info("consensus primary fail-back deferred, preferred node still behind",
			"preferred", id, "height", height, "signed_through", a.maxHeight, "primary", a.primary)
		return false

	case a.outranks(id):
		prev := a.primary
		a.primary = id
		a.lastReq = now
		a.grant(height)
		a.logger.Info("consensus primary signer failed back to preferred node", "from", prev, "to", id)
		return true

	default:
		return false
	}
}

// Release clears id as primary when its privval connection is no longer usable.
// This lets a connected standby take over immediately instead of waiting for the
// idle timeout. A stale disconnect from a non-primary target has no effect.
func (a *PrimaryArbiter) Release(id string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch {
	case a.primary != id:
		return false
	default:
		a.logger.Info("consensus primary signer disconnected", "primary", id)
		a.primary = ""
		a.lastReq = time.Time{}
		return true
	}
}

// grant records the height of a request the arbiter just allowed. Callers hold a.mu.
func (a *PrimaryArbiter) grant(height int64) {
	if height > a.maxHeight {
		a.maxHeight = height
	}
}

// Primary returns the current primary id ("" if none elected yet).
func (a *PrimaryArbiter) Primary() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.primary
}
