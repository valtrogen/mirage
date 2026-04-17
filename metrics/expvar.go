package metrics

import (
	"expvar"
	"fmt"
	"sort"
	"strconv"
	"sync"
)

// NewExpvarSink returns a Sink whose instruments are published under
// prefix on the standard expvar registry. Names are joined with "."
// (e.g. prefix "mirage_server" + counter "handshake_ok" yields
// "mirage_server.handshake_ok").
//
// Two sinks sharing the same prefix MUST NOT coexist; expvar's registry
// panics on duplicate publication.
func NewExpvarSink(prefix string) *ExpvarSink {
	return &ExpvarSink{
		prefix:     prefix,
		counters:   make(map[string]*expvarCounter),
		gauges:     make(map[string]*expvarGauge),
		histograms: make(map[string]*expvarHistogram),
	}
}

// ExpvarSink publishes mirage instruments through the expvar package.
type ExpvarSink struct {
	prefix string

	mu         sync.Mutex
	counters   map[string]*expvarCounter
	gauges     map[string]*expvarGauge
	histograms map[string]*expvarHistogram
}

// Counter returns the named counter, creating and publishing it on
// first reference.
func (s *ExpvarSink) Counter(name string) Counter {
	full := s.fullName(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.counters[name]
	if ok {
		return c
	}
	v := new(expvar.Int)
	expvar.Publish(full, v)
	c = &expvarCounter{v: v}
	s.counters[name] = c
	return c
}

// Gauge returns the named gauge, creating and publishing it on first
// reference.
func (s *ExpvarSink) Gauge(name string) Gauge {
	full := s.fullName(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.gauges[name]
	if ok {
		return g
	}
	v := new(expvar.Int)
	expvar.Publish(full, v)
	g = &expvarGauge{v: v}
	s.gauges[name] = g
	return g
}

// Histogram returns the named histogram, creating and publishing it on
// first reference. The exposed value is a JSON object with min, max,
// count, and a fixed set of percentiles (p50, p90, p99).
func (s *ExpvarSink) Histogram(name string) Histogram {
	full := s.fullName(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	h, ok := s.histograms[name]
	if ok {
		return h
	}
	h = &expvarHistogram{}
	expvar.Publish(full, expvar.Func(h.snapshotJSON))
	s.histograms[name] = h
	return h
}

func (s *ExpvarSink) fullName(name string) string {
	if s.prefix == "" {
		return name
	}
	return s.prefix + "." + name
}

type expvarCounter struct{ v *expvar.Int }

func (c *expvarCounter) Add(d uint64) {
	if d > 1<<62 {
		c.v.Add(int64(1 << 62))
		return
	}
	c.v.Add(int64(d))
}
func (c *expvarCounter) Value() uint64 { return uint64(c.v.Value()) }

type expvarGauge struct{ v *expvar.Int }

func (g *expvarGauge) Add(d int64) { g.v.Add(d) }
func (g *expvarGauge) Set(v int64) { g.v.Set(v) }
func (g *expvarGauge) Value() int64 { return g.v.Value() }

type expvarHistogram struct {
	mu      sync.Mutex
	samples []float64
}

func (h *expvarHistogram) Observe(v float64) {
	h.mu.Lock()
	h.samples = append(h.samples, v)
	h.mu.Unlock()
}

func (h *expvarHistogram) snapshotJSON() any {
	h.mu.Lock()
	cp := append([]float64(nil), h.samples...)
	h.mu.Unlock()
	if len(cp) == 0 {
		return rawJSON("{}")
	}
	sort.Float64s(cp)
	pct := func(p float64) float64 {
		idx := int(p * float64(len(cp)-1))
		return cp[idx]
	}
	return rawJSON(fmt.Sprintf(
		`{"count":%d,"min":%s,"max":%s,"p50":%s,"p90":%s,"p99":%s}`,
		len(cp),
		fmtFloat(cp[0]), fmtFloat(cp[len(cp)-1]),
		fmtFloat(pct(0.50)), fmtFloat(pct(0.90)), fmtFloat(pct(0.99)),
	))
}

func fmtFloat(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// rawJSON is a string that already encodes valid JSON; expvar emits it
// verbatim through its String() method.
type rawJSON string

func (r rawJSON) String() string { return string(r) }
