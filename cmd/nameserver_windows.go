//go:build windows

package cmd

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// systemNameserver returns the first usable DNS nameserver configured on any
// active network adapter, via the Windows GetAdaptersAddresses API.
func systemNameserver() (string, error) {
	nameservers, err := adapterNameservers()
	if err != nil {
		return "", fmt.Errorf("error: failed to determine the host DNS nameserver: %v; specify a DNS server with --server, e.g. --server 1.1.1.1 or --server 8.8.8.8", err)
	}
	for _, ns := range nameservers {
		if usableNameserver(ns) {
			return ns.String(), nil
		}
	}
	return "", fmt.Errorf("error: no DNS nameservers found on the host; specify a DNS server with --server, e.g. --server 1.1.1.1 or --server 8.8.8.8")
}

// adapterNameservers collects the DNS server addresses of all network
// adapters that are up, in adapter order.
func adapterNameservers() ([]net.IP, error) {
	// 15 KB is the size recommended by the GetAdaptersAddresses
	// documentation; grow and retry if it turns out to be insufficient.
	size := uint32(15 * 1024)
	for range 3 {
		buf := make([]byte, size)
		adapters := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(
			windows.AF_UNSPEC,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_UNICAST,
			0,
			adapters,
			&size,
		)
		if err == windows.ERROR_BUFFER_OVERFLOW {
			continue // size now holds the required buffer length.
		}
		if err != nil {
			return nil, err
		}

		var nameservers []net.IP
		for adapter := adapters; adapter != nil; adapter = adapter.Next {
			if adapter.OperStatus != windows.IfOperStatusUp || adapter.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
				continue
			}
			for dnsServer := adapter.FirstDnsServerAddress; dnsServer != nil; dnsServer = dnsServer.Next {
				if ip := dnsServer.Address.IP(); ip != nil {
					nameservers = append(nameservers, ip)
				}
			}
		}
		return nameservers, nil
	}
	return nil, fmt.Errorf("GetAdaptersAddresses: buffer size negotiation failed")
}
