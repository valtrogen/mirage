package proto

// ProtocolVersion is the wire-format version. It is mixed into key
// derivation but not sent on the wire.
const ProtocolVersion = "mirage/0.1"

// MasterKeySalt is the HKDF salt for master-key derivation. Changing
// it produces a hard fork in keying.
const MasterKeySalt = "mirage v1 master"
