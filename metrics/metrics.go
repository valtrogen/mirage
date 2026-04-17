package metrics

import (
	"sort"
	"sync"
	"sync/atomic"
)

// Counter is a monotonically increasing 64-bit integer.
type Counter interface {
	Add(delta uint64)
	Value() uint64
}

// Gauge is a 64-bit signed integer that may rise and fall.
type Gauge interface {
	Add(delta int64)
	Set(value int64)
	Value() int64
}

// Histogram records float64 samples. Implementations decide bucketing.
type Histogram interface {
	Observe(value float64)
}

// Sink hands out named instruments. The same name returned twice must
// give the same instrument, otherwise samples are silently lost.
//
// Sink methods MUST be safe for concurrent use. mirage's hot paths call
// them on every accepted handshake and every dispatched datagram.
type Sink interface {
	Counter(name string) Counter
	Gauge(name string) Gauge
	Histogram(name string) Histogram
}

// Discard is a Sink whose instruments accept and forget every sample.
// It is the default when a caller does not configure metrics.
var Discard Sink = discardSink{}

type discardSink struct{}

func (discardSink) Counter(string) Counter     { return discardCounter{} }
func (discardSink) Gauge(string) Gauge         { return discardGauge{} }
func (discardSink) Histogram(string) Histogram { return discardHistogram{} }

type discardCounter struct{}

func (discardCounter) Add(uint64)   {}
func (discardCounter) Value() uint64 { return 0 }

type discardGauge struct{}

func (discardGauge) Add(int64)  {}
func (discardGauge) Set(int64)  {}
func (discardGauge) Value() int64 { return 0 }

type discardHistogram struct{}

func (discardHistogram) Observe(float64) {}

// NewMemorySink returns an in-process Sink that keeps every value in
// memory. It is intended for tests and small embedded UIs; for real
// scrape endpoints use the expvar or Prometheus adapters.
func NewMemorySink() *MemorySink {
	return &MemorySink{
		counters:   make(map[string]*memCounter),
		gauges:     make(map[string]*memGauge),
		histograms: make(map[string]*memHistogram),
	}
}

// MemorySink is an in-process Sink that retains every reported value.
type MemorySink struct {
	mu         sync.Mutex
	counters   map[string]*memCounter
	gauges     map[string]*memGauge
	histograms map[string]*memHistogram
}

// Counter returns the named counter, creating it on first reference.
func (m *MemorySink) Counter(name string) Counter {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.counters[name]
	if !ok {
		c = &memCounter{}
		m.counters[name] = c
	}
	return c
}

// Gauge returns the named gauge, creating it on first reference.
func (m *MemorySink) Gauge(name string) Gauge {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.gauges[name]
	if !ok {
		g = &memGauge{}
		m.gauges[name] = g
	}
	return g
}

// Histogram returns the named histogram, creating it on first reference.
func (m *MemorySink) Histogram(name string) Histogram {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.histograms[name]
	if !ok {
		h = &memHistogram{}
		m.histograms[name] = h
	}
	return h
}

// CounterValue returns the current value of name, or zero if unseen.
func (m *MemorySink) CounterValue(name string) uint64 {
	m.mu.Lock()
	c, ok := m.counters[name]
	m.mu.Unlock()
	if !ok {
		return 0
	}
	return c.Value()
}

// GaugeValue returns the current value of name, or zero if unseen.
func (m *MemorySink) GaugeValue(name string) int64 {
	m.mu.Lock()
	g, ok := m.gauges[name]
	m.mu.Unlock()
	if !ok {
		return 0
	}
	return g.Value()
}

// HistogramSamples returns a sorted copy of every sample observed on
// name. The slice is fresh; callers may mutate it freely.
func (m *MemorySink) HistogramSamples(name string) []float64 {
	m.mu.Lock()
	h, ok := m.histograms[name]
	m.mu.Unlock()
	if !ok {
		return nil
	}
	return h.snapshot()
}

// CounterNames returns the set of counter names ever accessed, sorted.
func (m *MemorySink) CounterNames() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, 0, len(m.counters))
	for k := range m.counters {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type memCounter struct{ v atomic.Uint64 }

func (c *memCounter) Add(d uint64)   { c.v.Add(d) }
func (c *memCounter) Value() uint64 { return c.v.Load() }

type memGauge struct{ v atomic.Int64 }

func (g *memGauge) Add(d int64)  { g.v.Add(d) }
func (g *memGauge) Set(v int64)  { g.v.Store(v) }
func (g *memGauge) Value() int64 { return g.v.Load() }

type memHistogram struct {
	mu      sync.Mutex
	samples []float64
}

func (h *memHistogram) Observe(v float64) {
	h.mu.Lock()
	h.samples = append(h.samples, v)
	h.mu.Unlock()
}

func (h *memHistogram) snapshot() []float64 {
	h.mu.Lock()
	out := append([]float64(nil), h.samples...)
	h.mu.Unlock()
	sort.Float64s(out)
	return out
}
