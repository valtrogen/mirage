// Package transport wraps the underlying QUIC stack with the hooks
// mirage needs: Initial packet interception, behavior-alignment knobs,
// and congestion-controller signals for the padder.
package transport
