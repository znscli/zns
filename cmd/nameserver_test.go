package cmd

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUsableNameserver(t *testing.T) {
	assert.True(t, usableNameserver(net.ParseIP("192.168.1.1")))
}

func TestUsableNameserver_ipv6(t *testing.T) {
	assert.True(t, usableNameserver(net.ParseIP("2606:4700:4700::1111")))
}

func TestUsableNameserver_nil(t *testing.T) {
	assert.False(t, usableNameserver(nil))
}

func TestUsableNameserver_unspecified(t *testing.T) {
	assert.False(t, usableNameserver(net.ParseIP("0.0.0.0")))
	assert.False(t, usableNameserver(net.ParseIP("::")))
}

// Windows reports the deprecated site-local placeholders fec0:0:0:ffff::1-3
// on adapters without configured DNS servers; they must be skipped.
func TestUsableNameserver_siteLocalPlaceholder(t *testing.T) {
	assert.False(t, usableNameserver(net.ParseIP("fec0:0:0:ffff::1")))
	assert.False(t, usableNameserver(net.ParseIP("fec0:0:0:ffff::2")))
	assert.False(t, usableNameserver(net.ParseIP("fec0:0:0:ffff::3")))
}
