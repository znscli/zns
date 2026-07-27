package cmd

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUsableNameserver(t *testing.T) {
	assert.True(t, usableNameserver(netip.MustParseAddr("192.168.1.1")))
}

func TestUsableNameserver_ipv6(t *testing.T) {
	assert.True(t, usableNameserver(netip.MustParseAddr("2606:4700:4700::1111")))
}

func TestUsableNameserver_invalid(t *testing.T) {
	assert.False(t, usableNameserver(netip.Addr{}))
}

func TestUsableNameserver_unspecified(t *testing.T) {
	assert.False(t, usableNameserver(netip.MustParseAddr("0.0.0.0")))
	assert.False(t, usableNameserver(netip.MustParseAddr("::")))
}

// A link-local IPv6 nameserver cannot be dialed without a zone index.
func TestUsableNameserver_linkLocalWithoutZone(t *testing.T) {
	assert.False(t, usableNameserver(netip.MustParseAddr("fe80::1")))
}

func TestUsableNameserver_linkLocalWithZone(t *testing.T) {
	assert.True(t, usableNameserver(netip.MustParseAddr("fe80::1%en0")))
}

// Windows reports the deprecated site-local placeholders fec0:0:0:ffff::1-3
// on adapters without configured DNS servers; they must be skipped.
func TestUsableNameserver_siteLocalPlaceholder(t *testing.T) {
	assert.False(t, usableNameserver(netip.MustParseAddr("fec0:0:0:ffff::1")))
	assert.False(t, usableNameserver(netip.MustParseAddr("fec0:0:0:ffff::2")))
	assert.False(t, usableNameserver(netip.MustParseAddr("fec0:0:0:ffff::3")))
}
