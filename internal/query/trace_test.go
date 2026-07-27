package query

import (
	"net"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// rootServerAddr is the root nameserver the test traces start from.
const rootServerAddr = "198.41.0.4:53"

// referralClient serves a two-level delegation: root refers to "com.", the
// com. servers refer to "example.com.", whose servers answer.
type referralClient struct {
	// Queried records the addresses queried, in order.
	Queried []string
	// RecursionDesired records whether any query asked for recursion.
	RecursionDesired bool
}

func ns(zone, server string) *dns.NS {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
		Ns:  server,
	}
}

func glue(name, addr string) *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.ParseIP(addr),
	}
}

func (c *referralClient) Exchange(req *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	c.Queried = append(c.Queried, addr)
	if req.RecursionDesired {
		c.RecursionDesired = true
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	switch addr {
	case rootServerAddr: // Root server.
		resp.Ns = []dns.RR{ns("com.", "a.gtld-servers.net.")}
		resp.Extra = []dns.RR{glue("a.gtld-servers.net.", "192.0.2.1")}
	case "192.0.2.1:53": // com. server.
		resp.Ns = []dns.RR{ns("example.com.", "ns1.example.com.")}
		resp.Extra = []dns.RR{glue("ns1.example.com.", "192.0.2.2")}
	case "192.0.2.2:53": // example.com. server.
		resp.Authoritative = true
		resp.Answer = []dns.RR{glue("example.com.", "93.184.216.34")}
	}
	return resp, time.Millisecond, nil
}

func traceClient(t *testing.T) (*QueryClient, *referralClient) {
	t.Helper()
	mock := &referralClient{}
	client := NewQueryClient("192.0.2.53:53", mock, hclog.NewNullLogger())
	client.RootServers = []string{rootServerAddr}
	return client, mock
}

func TestTrace_followsDelegations(t *testing.T) {
	client, mock := traceClient(t)

	steps, err := client.Trace("example.com", dns.TypeA)

	assert.NoError(t, err)
	assert.Equal(t, []string{rootServerAddr, "192.0.2.1:53", "192.0.2.2:53"}, mock.Queried)
	assert.Len(t, steps, 3)
}

func TestTrace_lastStepHoldsTheAnswer(t *testing.T) {
	client, _ := traceClient(t)

	steps, err := client.Trace("example.com", dns.TypeA)

	assert.NoError(t, err)
	last := steps[len(steps)-1]
	assert.Len(t, last.Msg.Answer, 1)
	assert.Equal(t, "192.0.2.2:53", last.Server)
}

// TestTrace_referralStepsCarryTheDelegation exposes each referral's NS
// records, which is what the trace output renders.
func TestTrace_referralStepsCarryTheDelegation(t *testing.T) {
	client, _ := traceClient(t)

	steps, err := client.Trace("example.com", dns.TypeA)

	assert.NoError(t, err)
	assert.Equal(t, "com.", steps[0].Zone)
	assert.Len(t, steps[0].Msg.Ns, 1)
	assert.Equal(t, "example.com.", steps[1].Zone)
}

// TestTrace_iterativeQueriesOnly guards that a trace never asks a server to
// recurse: each step must be answered from that server's own zone.
func TestTrace_iterativeQueriesOnly(t *testing.T) {
	client, mock := traceClient(t)

	_, err := client.Trace("example.com", dns.TypeA)

	assert.NoError(t, err)
	assert.False(t, mock.RecursionDesired)
}

// deadEndClient refers every query back to a zone it never delegates away
// from, which would loop forever without a depth limit.
type deadEndClient struct{ calls int }

func (c *deadEndClient) Exchange(req *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	c.calls++
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Ns = []dns.RR{ns("com.", "a.gtld-servers.net.")}
	resp.Extra = []dns.RR{glue("a.gtld-servers.net.", "192.0.2.1")}
	return resp, time.Millisecond, nil
}

func TestTrace_stopsOnDelegationLoop(t *testing.T) {
	mock := &deadEndClient{}
	client := NewQueryClient("192.0.2.53:53", mock, hclog.NewNullLogger())
	client.RootServers = []string{rootServerAddr}

	_, err := client.Trace("example.com", dns.TypeA)

	assert.Error(t, err)
	assert.Less(t, mock.calls, 40, "trace must stop rather than loop")
}

func TestRootServers(t *testing.T) {
	client := NewQueryClient("1.1.1.1:53", &MockDNSClient{}, hclog.NewNullLogger())

	assert.Len(t, client.RootServers, 13)
	assert.Contains(t, client.RootServers, rootServerAddr) // a.root-servers.net
}
