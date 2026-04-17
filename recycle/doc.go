// Package recycle implements connection rotation. The server tracks
// per-connection age and bytes; once either crosses a randomised
// threshold it sends a ConnectionRecycleHint and starts a graceful
// drain while the client moves new streams to a fresh connection.
package recycle
