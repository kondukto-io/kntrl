package parser

import (
	"bufio"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/kondukto-io/kntrl/internal/core/domain"
)

const (
	localLoopback = "127.0.0.1"
	linkLocal     = "169.254.169.254"
	azureMeta     = "168.63.129.16"
)

func ToDataJson(allowed_hosts, allowed_ips string, ghrange, localrange bool) *domain.Data {
	hosts, ips := getDNSServers()
	hosts = append(hosts, parseAllowedHosts(allowed_hosts)...)
	ips = append(ips, parseAllowedIPAddr(allowed_ips)...)
	ips = append(ips, host2ip(hosts)...)

	return &domain.Data{
		AllowedHosts:       hosts,
		AllowedIPs:         ips,
		AllowGithubMeta:    ghrange,
		AllowLocalIPRanges: localrange,
	}
}

func parseAllowedIPAddr(ips string) (iplist []net.IP) {
	for _, ip := range strings.Split(ips, ",") {
		if i := net.ParseIP(ip); i == nil {
			continue
		} else {
			iplist = append(iplist, i.To4())
		}
	}

	iplist = append(iplist,
		net.ParseIP(localLoopback).To4(),
		net.ParseIP(linkLocal).To4(),
		net.ParseIP(azureMeta).To4(),
	)

	return iplist
}

func parseAllowedHosts(hosts string) (hl []string) {
	for _, host := range strings.Split(hosts, ",") {
		if res, err := url.Parse(host); err != nil && res.Host != "" {
			hl = append(hl, res.Host)
		}
	}

	return hl
}

// find a better solution
func host2ip(hosts []string) (ipl []net.IP) {
	for _, h := range hosts {
		ip, err := net.LookupIP(h)
		if err != nil {
			continue
		}
		for _, v := range ip {
			if ipv4 := v.To4(); ipv4 != nil {
				ipl = append(ipl, ipv4)
			}
		}
	}
	return
}

func getDNSServers() (hosts []string, ips []net.IP) {
	const resolvconf = "/etc/resolv.conf"

	file, err := os.Open(resolvconf)
	if err != nil {
		return nil, nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		if len(fields) >= 2 && fields[0] == "nameserver" {
			if ok := net.ParseIP(fields[1]); ok == nil {
				hosts = append(hosts, fields[1])
			} else {
				ips = append(ips, net.ParseIP(fields[1]))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil
	}

	return
}
