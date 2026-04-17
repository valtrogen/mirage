package adapter

import "context"

// TrafficReporter receives byte-counter deltas from the mirage data plane.
//
// Report is called from the data path. Implementations should return
// quickly; persistent storage or network publication should be done on a
// background goroutine.
//
// bytesUp and bytesDown are deltas since the previous Report call for the
// same UserID, not cumulative totals. mirage will not call Report
// concurrently for the same UserID.
type TrafficReporter interface {
	Report(ctx context.Context, userID UserID, bytesUp, bytesDown uint64)
}

// TrafficReporterFunc adapts a function to TrafficReporter.
type TrafficReporterFunc func(ctx context.Context, userID UserID, bytesUp, bytesDown uint64)

// Report implements TrafficReporter.
func (f TrafficReporterFunc) Report(ctx context.Context, userID UserID, bytesUp, bytesDown uint64) {
	f(ctx, userID, bytesUp, bytesDown)
}

// NopTrafficReporter discards every report. Useful in tests.
var NopTrafficReporter TrafficReporter = TrafficReporterFunc(
	func(context.Context, UserID, uint64, uint64) {},
)
