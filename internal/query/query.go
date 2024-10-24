package query

import (
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"sync"
)

var (
	// QueryTypes holds the DNS query types supported by zns for executing DNS queries.
	QueryTypes = map[string]uint16{
		"A":     dns.TypeA,
		"AAAA":  dns.TypeAAAA,
		"CNAME": dns.TypeCNAME,
		"MX":    dns.TypeMX,
		"NS":    dns.TypeNS,
		"PTR":   dns.TypePTR,
		"SOA":   dns.TypeSOA,
		"TXT":   dns.TypeTXT,
	}
)

// Querier is an interface for querying DNS records.
type Querier interface {
	Query(domain string, qtype uint16) (*dns.Msg, error)
	MultiQuery(domain string, qtypes []uint16) ([]*dns.Msg, error)
}

// Query implements the Querier interface.
type Query struct {
	Server string
	hclog.Logger
}

// NewQuerier creates a new Querier with the specified server.
func NewQuerier(server string, logger hclog.Logger) Querier {
	return &Query{Server: server, Logger: logger}
}

// MultiQuery performs DNS queries for multiple types concurrently.
func (q *Query) MultiQuery(domain string, qtypes []uint16) ([]*dns.Msg, error) {
	var errors *multierror.Error
	var wg sync.WaitGroup
	var mu sync.Mutex

	messages := make([]*dns.Msg, len(qtypes))

	for i, qtype := range qtypes {
		wg.Add(1)
		go func(i int, qtype uint16) {
			defer wg.Done()
			msg, err := q.Query(domain, qtype)
			mu.Lock()
			messages[i] = msg
			errors = multierror.Append(errors, err)
			mu.Unlock()
		}(i, qtype)
	}

	wg.Wait()

	return messages, errors.ErrorOrNil()
}

// Query performs the DNS query and returns the response and any error encountered.
func (q *Query) Query(domain string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)

	q.Logger.Debug("Querying DNS server", "server", q.Server, "domain", domain, "qtype", dns.TypeToString[qtype])

	client := new(dns.Client)
	resp, rtt, err := client.Exchange(msg, q.Server)
	if err != nil {
		return nil, err
	}

	q.Logger.Debug("Received DNS response", "server", q.Server, "domain", domain, "qtype", dns.TypeToString[qtype], "rcode", dns.RcodeToString[resp.Rcode])
	q.Logger.Debug("Round trip time", "rtt", rtt)

	return resp, nil
}
