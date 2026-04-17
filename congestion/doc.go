// Package congestion defines the interface a mirage client uses to
// throttle its sender, plus a NoOp implementation and the supporting
// types (RTT statistics, bandwidth, byte counts).
//
// The data plane wires every outbound packet, every received ACK and
// every detected loss into a Controller. Implementations decide when
// the sender may transmit, how many bytes may be in flight, and at
// what pacing rate. The default Controller is the no-op sender which
// imposes no congestion limit; production deployments install
// Controller bbr2 (see github.com/valtrogen/mirage/congestion/bbr2).
//
// The split between this package and the algorithm packages keeps the
// algorithm code free of mirage-internal dependencies, so individual
// controllers can be unit-tested without bringing up a full client.
package congestion
