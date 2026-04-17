package handshake

import "container/list"

// sessionLRU caches *SessionState entries keyed by 4-tuple string with
// a hard ceiling and least-recently-used eviction. It is not safe for
// concurrent use; the dispatcher serialises all access through its own
// mutex.
type sessionLRU struct {
	cap   int
	ll    *list.List
	index map[string]*list.Element
}

type lruEntry struct {
	key string
	val *SessionState
}

func newSessionLRU(cap int) *sessionLRU {
	if cap <= 0 {
		cap = 1
	}
	return &sessionLRU{
		cap:   cap,
		ll:    list.New(),
		index: make(map[string]*list.Element, cap),
	}
}

// Get returns the value for key. Touch indicates whether the access
// should refresh the LRU position; the dispatcher disables Touch for
// reaper sweeps that should not promote stale entries.
func (l *sessionLRU) Get(key string, touch bool) (*SessionState, bool) {
	e, ok := l.index[key]
	if !ok {
		return nil, false
	}
	if touch {
		l.ll.MoveToFront(e)
	}
	return e.Value.(*lruEntry).val, true
}

// Put installs val for key. It returns the *SessionState that was
// evicted to make room, or nil if no eviction was needed.
func (l *sessionLRU) Put(key string, val *SessionState) *SessionState {
	if e, ok := l.index[key]; ok {
		e.Value.(*lruEntry).val = val
		l.ll.MoveToFront(e)
		return nil
	}
	e := l.ll.PushFront(&lruEntry{key: key, val: val})
	l.index[key] = e
	if l.ll.Len() <= l.cap {
		return nil
	}
	tail := l.ll.Back()
	ent := tail.Value.(*lruEntry)
	l.ll.Remove(tail)
	delete(l.index, ent.key)
	return ent.val
}

// Delete removes key from the cache. It returns whether the key was
// present.
func (l *sessionLRU) Delete(key string) bool {
	e, ok := l.index[key]
	if !ok {
		return false
	}
	l.ll.Remove(e)
	delete(l.index, key)
	return true
}

// Len reports the current size.
func (l *sessionLRU) Len() int { return l.ll.Len() }

// ForEach calls fn for every (key, val) currently in the cache. Order
// is not specified; fn must not mutate the cache.
func (l *sessionLRU) ForEach(fn func(key string, val *SessionState)) {
	for e := l.ll.Front(); e != nil; e = e.Next() {
		ent := e.Value.(*lruEntry)
		fn(ent.key, ent.val)
	}
}
