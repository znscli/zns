package query

import (
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// maxTraceDepth bounds a delegation walk, so a zone that refers back to
// itself stops instead of looping.
const maxTraceDepth = 20

// rootServers are the IANA root nameservers, where a delegation walk starts.
// See https://www.iana.org/domains/root/servers.
var rootServers = []string{
	"198.41.0.4:53",     // a.root-servers.net
	"170.247.170.2:53",  // b.root-servers.net
	"192.33.4.12:53",    // c.root-servers.net
	"199.7.91.13:53",    // d.root-servers.net
	"192.203.230.10:53", // e.root-servers.net
	"192.5.5.241:53",    // f.root-servers.net
	"192.112.36.4:53",   // g.root-servers.net
	"198.97.190.53:53",  // h.root-servers.net
	"192.36.148.17:53",  // i.root-servers.net
	"192.58.128.30:53",  // j.root-servers.net
	"193.0.14.129:53",   // k.root-servers.net
	"199.7.83.42:53",    // l.root-servers.net
	"202.12.27.33:53",   // m.root-servers.net
}

// TraceStep is one step of a delegation walk: the response a server gave,
// and, for a referral, the zone it delegated.
type TraceStep struct {
	// Server is the nameserver that answered.
	Server string
	// Zone is the delegated zone for a referral, empty for a final answer.
	Zone string
	// Msg is the response, holding either a referral in its authority
	// section or the answer.
	Msg *dns.Msg
}

// Trace walks the delegation chain for a domain, starting at the root
// nameservers and following referrals until a server answers
// authoritatively. Queries are iterative: no server is asked to recurse.
func (q *QueryClient) Trace(domain string, qtype uint16) ([]TraceStep, error) {
	name := dns.Fqdn(domain)
	servers := q.RootServers
	zone := "."

	var steps []TraceStep
	for depth := 0; depth < maxTraceDepth; depth++ {
		server, resp, err := q.askAny(servers, name, qtype)
		if err != nil {
			return steps, err
		}

		// An answer, or an authority section holding no delegation (e.g. the
		// SOA of a NODATA response), ends the walk.
		delegation, next := referral(resp)
		if len(resp.Answer) > 0 || delegation == "" {
			steps = append(steps, TraceStep{Server: server, Msg: resp})
			return steps, nil
		}
		// A referral that does not move down the tree cannot be followed.
		if !progresses(zone, delegation) {
			return steps, fmt.Errorf("lame delegation: %s referred %s back to %s", server, name, delegation)
		}

		steps = append(steps, TraceStep{Server: server, Zone: delegation, Msg: resp})
		zone = delegation
		if servers, err = q.addresses(next, resp); err != nil {
			return steps, err
		}
	}
	return steps, fmt.Errorf("delegation for %s not resolved after %d referrals", domain, maxTraceDepth)
}

// askAny queries the given servers in order and returns the first response.
func (q *QueryClient) askAny(servers []string, name string, qtype uint16) (string, *dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)
	msg.RecursionDesired = false // A trace follows delegations itself.
	msg.SetEdns0(4096, q.DNSSEC)

	var lastErr error
	for _, server := range servers {
		q.Debug("Tracing delegation", "server", server, "domain", name, "qtype", dns.TypeToString[qtype])
		resp, _, err := q.Client.Exchange(msg, server)
		if err != nil {
			lastErr = err
			continue
		}
		return server, resp, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no nameservers to query")
	}
	return "", nil, lastErr
}

// referral reports the zone a response delegates and the nameserver names
// responsible for it, or an empty zone when the response holds no delegation.
func referral(resp *dns.Msg) (string, []string) {
	var delegated string
	var servers []string
	for _, rr := range resp.Ns {
		rec, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		if delegated == "" {
			delegated = rec.Hdr.Name
		}
		if strings.EqualFold(rec.Hdr.Name, delegated) {
			servers = append(servers, rec.Ns)
		}
	}
	return delegated, servers
}

// progresses reports whether a referral moves down the tree, towards the
// name being traced.
func progresses(zone, delegated string) bool {
	return !strings.EqualFold(zone, delegated) && dns.IsSubDomain(zone, delegated)
}

// addresses resolves nameserver names to server addresses, preferring the
// glue records shipped with the referral and falling back to the configured
// resolver.
func (q *QueryClient) addresses(nameservers []string, resp *dns.Msg) ([]string, error) {
	var servers []string
	for _, rr := range resp.Extra {
		switch rec := rr.(type) {
		case *dns.A:
			if matchesAny(rec.Hdr.Name, nameservers) {
				servers = append(servers, net.JoinHostPort(rec.A.String(), "53"))
			}
		case *dns.AAAA:
			if matchesAny(rec.Hdr.Name, nameservers) {
				servers = append(servers, net.JoinHostPort(rec.AAAA.String(), "53"))
			}
		}
	}
	if len(servers) > 0 {
		return servers, nil
	}

	// No glue: resolve a nameserver name through the configured resolver.
	for _, name := range nameservers {
		resp, err := q.query(name, dns.TypeA)
		if err != nil {
			continue
		}
		for _, rr := range resp.Answer {
			if rec, ok := rr.(*dns.A); ok {
				servers = append(servers, net.JoinHostPort(rec.A.String(), "53"))
			}
		}
		if len(servers) > 0 {
			return servers, nil
		}
	}
	return nil, fmt.Errorf("no addresses found for nameservers %s", strings.Join(nameservers, ", "))
}

func matchesAny(name string, names []string) bool {
	for _, candidate := range names {
		if strings.EqualFold(name, candidate) {
			return true
		}
	}
	return false
}
