package cmd

import (
	"bytes"
	"net"
)

// siteLocalDNSPrefix is the deprecated IPv6 site-local prefix
// (fec0:0:0:ffff::/64) that Windows reports as placeholder DNS servers on
// adapters without configured DNS.
var siteLocalDNSPrefix = []byte{0xfe, 0xc0, 0, 0, 0, 0, 0xff, 0xff}

// usableNameserver reports whether ip is a usable DNS nameserver address.
func usableNameserver(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() {
		return false
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return false
	}
	return !bytes.HasPrefix(ip16, siteLocalDNSPrefix)
}
