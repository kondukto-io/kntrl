package utils

import (
	"encoding/binary"
	"fmt"
	"net"
	"os/user"
	"regexp"
	"strings"

	"github.com/cilium/ebpf"
)

func IsRoot() bool {
	u, err := user.Current()
	if err != nil {
		return false
	}

	return u.Uid == "0"
}

// parse eBPF program name from *ebpf.Program struct
func ParseProgramName(e *ebpf.Program) string {
	input := e.String()

	regexPattern := `\((.*?)\)`

	// Compile the regular expression pattern
	regex := regexp.MustCompile(regexPattern)

	// Find the match in the input string
	matches := regex.FindStringSubmatch(input)
	if len(matches) == 2 {
		return matches[1]
	}

	return "(notparsed)" + input
}

// returns the given protock name
// TODO: find better alternative
func GetProtocol(p uint8) string {
	protocolNames := map[uint8]string{
		1:  "icmp", // Protocol number for ICMP is 1.
		6:  "tcp",  // Protocol number for TCP is 6.
		17: "udp",  // Protocol number for UDP is 17.
		// Add more protocol numbers and their names if needed.
	}

	if name, ok := protocolNames[p]; ok {
		return name
	}

	return "-"
}

// trim NULL bytes (in the event.Comm)
func TrimNullBytes(p [16]uint8) string {
	var comm string
	for _, v := range p {
		if v == 0 {
			continue
		}
		comm = fmt.Sprintf("%s%s", comm, string(v))
	}

	return comm
}

// lookup IP address and trim suffix (".")
// in the doamin name
func LookupAndTrim(ip net.IP) ([]string, error) {
	names, err := net.LookupAddr(ip.String())
	if err != nil {
		return names, err
	}

	for k, v := range names {
		names[k] = strings.TrimSuffix(v, ".")
	}

	return names, err
}

// intToIP converts IPv4 number to net.IP
func IntToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	//binary.BigEndian.PutUint32(ip, ipNum)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}
