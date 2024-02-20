package utils

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
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

// ParseHosts function parses the given hosts (or IP addresses)
// runs a lookup function, validates and ignores IPv6
func ParseHosts(ips string) ([]net.IP, error) {
	allowedIPAddress := []string{
		"127.0.0.1",
		"169.254.169.254",
		"168.63.129.16",
		//"20.102.39.57",
		//"140.82.112.21",
		//"52.239.172.36",
	}

	var retval []net.IP
	for _, ip := range func(ips string) []string {
		i := strings.Split(ips, ",")
		i = append(i, getDNSServers()...)
		i = append(i, allowedIPAddress...)
		return i
	}(ips) {
		if i := net.ParseIP(ip); i == nil {
			hip, err := lookup(ip)
			if err != nil {
				continue
			}
			// accept iPv4 only
			for _, v := range hip {
				if ipv4 := v.To4(); ipv4 != nil {
					retval = append(retval, ipv4)
				}
			}
		} else {
			// accept iPv4 only
			if ipv4 := i.To4(); ipv4 != nil {
				retval = append(retval, ipv4)
			}
		}
	}

	if len(retval) == 0 {
		return retval, errors.New("error: invalid IP or hostname")
	}

	return retval, nil
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
		1:  "ICMP", // Protocol number for ICMP is 1.
		6:  "TCP",  // Protocol number for TCP is 6.
		17: "UDP",  // Protocol number for UDP is 17.
		// Add more protocol numbers and their names if needed.
	}

	if name, ok := protocolNames[p]; ok {
		return name
	}

	return "-"
}

// trim NULL bytes (in the event.Comm)
func XTrim(p [16]uint8) string {
	var comm string
	for _, v := range p {
		if v == 0 {
			continue
		}
		comm = fmt.Sprintf("%s%s", comm, string(v))
	}

	return comm
}

// intToIP converts IPv4 number to net.IP
func IntToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	//binary.BigEndian.PutUint32(ip, ipNum)
	binary.LittleEndian.PutUint32(ip, ipNum)
	return ip
}

// unexported functions
func lookup(s string) ([]net.IP, error) {
	add, err := net.LookupIP(s)
	if err != nil {
		return add, err
	}

	return add, nil
}

func getDNSServers() []string {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	defer file.Close()

	var dnsServers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) >= 2 && fields[0] == "nameserver" {
			dnsServers = append(dnsServers, fields[1])
		}
	}

	if err := scanner.Err(); err != nil {
		return nil
	}

	return dnsServers
}
