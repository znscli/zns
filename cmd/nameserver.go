package cmd

import "net/netip"

// siteLocalDNSPrefix is the deprecated IPv6 site-local prefix
// (fec0:0:0:ffff::/64) that Windows reports as placeholder DNS servers on
// adapters without configured DNS.
var siteLocalDNSPrefix = netip.MustParsePrefix("fec0:0:0:ffff::/64")

// usableNameserver reports whether addr is a DNS nameserver zns can query.
// Link-local addresses are only usable with a zone, since dialing them
// without one fails.
func usableNameserver(addr netip.Addr) bool {
	switch {
	case !addr.IsValid(), addr.IsUnspecified():
		return false
	case addr.IsLinkLocalUnicast() && addr.Zone() == "":
		return false
	case siteLocalDNSPrefix.Contains(addr.WithZone("")):
		return false
	default:
		return true
	}
}
