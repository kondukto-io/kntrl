package domain

// ConnectionKey matches struct connection_key in sensor_defs.h. The cookie is
// assigned by the kernel and cannot be chosen by the connecting process.
type ConnectionKey struct {
	Cookie   uint64
	Address  [16]byte
	Port     uint16
	Protocol uint8
	Family   uint8
	Pad      uint32
}

// DNSResolverKey keeps IPv4 addresses distinct from zero-padded IPv6 addresses.
type DNSResolverKey struct {
	Address [16]byte
	Family  uint32
}
