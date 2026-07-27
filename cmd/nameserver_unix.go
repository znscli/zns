//go:build !windows

package cmd

import (
	"fmt"

	"github.com/miekg/dns"
)

const resolveConfPath = "/etc/resolv.conf"

// systemNameserver returns the first DNS nameserver configured on the host.
func systemNameserver() (string, error) {
	conf, err := dns.ClientConfigFromFile(resolveConfPath)
	if err != nil {
		return "", fmt.Errorf("error: failed to read %s: %v; specify a DNS server with --server, e.g. --server 1.1.1.1 or --server 8.8.8.8", resolveConfPath, err)
	}
	if len(conf.Servers) == 0 {
		return "", fmt.Errorf("error: no DNS nameservers found in %s; specify a DNS server with --server, e.g. --server 1.1.1.1 or --server 8.8.8.8", resolveConfPath)
	}
	return conf.Servers[0], nil
}
