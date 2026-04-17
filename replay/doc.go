// Package replay provides anti-replay primitives:
//
//   - a time-window key derived from HKDF(master_key, window_id);
//   - a per-user 64-bit sliding window for precise replays inside the
//     current window.
package replay
