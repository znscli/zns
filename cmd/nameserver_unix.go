//go:build !windows

package cmd

import (
	"fmt"
	"net/netip"

	"github.com/miekg/dns"
)

const resolveConfPath = "/etc/resolv.conf"

// systemNameserver returns the first usable DNS nameserver configured on the
// host.
func systemNameserver() (string, error) {
	conf, err := dns.ClientConfigFromFile(resolveConfPath)
	if err != nil {
		return "", fmt.Errorf("error: failed to read %s: %v; specify a DNS server with --server, e.g. --server 1.1.1.1 or --server 8.8.8.8", resolveConfPath, err)
	}
	for _, server := range conf.Servers {
		// A server that does not parse as an address is a hostname, which is
		// unusual in resolv.conf but valid; leave it to the resolver.
		if addr, parseErr := netip.ParseAddr(server); parseErr == nil && !usableNameserver(addr) {
			continue
		}
		return server, nil
	}
	return "", fmt.Errorf("error: no usable DNS nameservers found in %s; specify a DNS server with --server, e.g. --server 1.1.1.1 or --server 8.8.8.8", resolveConfPath)
}
