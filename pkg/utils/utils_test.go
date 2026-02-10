package utils

import (
	"net"
	"testing"
)

func TestGetProtocol(t *testing.T) {
	tests := []struct {
		input    uint8
		expected string
	}{
		{1, "icmp"},
		{6, "tcp"},
		{17, "udp"},
		{99, "-"},
	}

	for _, tc := range tests {
		result := GetProtocol(tc.input)
		if result != tc.expected {
			t.Errorf("GetProtocol(%d) = %q, want %q", tc.input, result, tc.expected)
		}
	}
}

func TestTrimNullBytes(t *testing.T) {
	var input [16]uint8
	copy(input[:], "curl")
	result := TrimNullBytes(input)
	if result != "curl" {
		t.Errorf("TrimNullBytes() = %q, want %q", result, "curl")
	}
}

func TestIntToIP(t *testing.T) {
	// 127.0.0.1 in little-endian is 0x0100007F
	ip := IntToIP(0x0100007F)
	expected := net.IPv4(127, 0, 0, 1).To4()
	if !ip.Equal(expected) {
		t.Errorf("IntToIP(0x0100007F) = %v, want %v", ip, expected)
	}
}

func TestIsRoot(t *testing.T) {
	// Just ensure it doesn't panic
	_ = IsRoot()
}
