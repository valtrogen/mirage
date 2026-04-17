// Package padder injects keepalive padding during application-layer
// idle when the BBR controller is in ProbeRTT or a low-bandwidth state,
// so flows do not display long silent gaps followed by sudden bursts.
package padder
