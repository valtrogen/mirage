// Package metrics defines the small instrumentation surface mirage's
// internal packages emit on. Concrete sinks live behind interfaces so a
// caller may bind mirage to expvar, Prometheus, OpenTelemetry, or
// nothing at all without dragging extra dependencies into the core.
//
// Three primitives cover everything mirage emits:
//
//   - Counter is a monotonically increasing 64-bit integer (handshakes,
//     dropped packets, retransmits).
//   - Gauge is a 64-bit integer that rises and falls (live connections,
//     queue depth).
//   - Histogram observes float64 samples (handshake latency,
//     dispatcher decision latency).
//
// The default Sink is Discard, which makes every operation a no-op.
// Production callers wire a real Sink via the Sink field on
// handshake.Server (and similar entry points).
package metrics
