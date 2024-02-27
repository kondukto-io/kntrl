package utils

import (
	"net"
	"reflect"
	"testing"
)

func TestParseAllowedIP(t *testing.T) {
	// Mocking localIPRanges for testing
	var expIPs []net.IP
	{
		expIPs = append(expIPs, net.ParseIP(githubMetaIPAddress))
		expIPs = append(expIPs, net.ParseIP(azureIPAddress))
	}

	var expRanges []string
	{
		expRanges = append(expRanges, localIPRanges...)
	}

	testCases := []struct {
		input          string
		expectedIPs    []net.IP
		expectedRanges []string
	}{
		{
			input:          "192.168.0.1,192.168.0.2,10.0.0.0/24",
			expectedIPs:    []net.IP{net.ParseIP("192.168.0.1"), net.ParseIP("192.168.0.2")},
			expectedRanges: []string{"192.168.1.0/24", "10.0.0.0/8", "10.0.0.0/24"},
		},
		{
			input:          "192.168.0.1/24,8.8.8.8",
			expectedIPs:    []net.IP{net.ParseIP("8.8.8.8")},
			expectedRanges: []string{"192.168.1.0/24", "10.0.0.0/8"},
		},
		// Add more test cases as needed
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			ips, ranges := ParseAllowedIP(tc.input)

			if !reflect.DeepEqual(ips, tc.expectedIPs) {
				t.Errorf("unexpected IPs, expected: %v, got: %v", tc.expectedIPs, ips)
			}

			if !reflect.DeepEqual(ranges, tc.expectedRanges) {
				t.Errorf("unexpected ranges, expected: %v, got: %v", tc.expectedRanges, ranges)
			}
		})
	}
}
