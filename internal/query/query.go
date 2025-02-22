package query

import (
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
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

type DNSClient interface {
	Exchange(*dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type QueryClient struct {
	Server string
	Client DNSClient
	hclog.Logger
}

// NewQueryClient initializes a QueryClient with the given DNS server, client, and logger.
// The provided client must implement the Exchange method for DNS queries.
func NewQueryClient(server string, client DNSClient, logger hclog.Logger) *QueryClient {
	return &QueryClient{
		Server: server,
		Client: client,
		Logger: logger,
	}
}

// MultiQuery performs DNS queries for multiple types concurrently.
func (q *QueryClient) MultiQuery(domain string, qtypes []uint16) ([]*dns.Msg, error) {
	var errors *multierror.Error
	var wg sync.WaitGroup
	var mu sync.Mutex

	messages := make([]*dns.Msg, len(qtypes))

	for i, qtype := range qtypes {
		wg.Add(1)
		go func(i int, qtype uint16) {
			defer wg.Done()
			msg, err := q.query(domain, qtype)
			mu.Lock()
			messages[i] = msg
			errors = multierror.Append(errors, err)
			mu.Unlock()
		}(i, qtype)
	}

	wg.Wait()

	return messages, errors.ErrorOrNil()
}

// query performs the DNS query and returns the response and any error encountered.
func (q *QueryClient) query(domain string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)

	q.Logger.Debug("Querying DNS server", "server", q.Server, "domain", domain, "qtype", dns.TypeToString[qtype])

	resp, rtt, err := q.Client.Exchange(msg, q.Server)
	if err != nil {
		return nil, err
	}

	q.Logger.Debug("Received DNS response", "server", q.Server, "domain", domain, "qtype", dns.TypeToString[qtype], "rcode", dns.RcodeToString[resp.Rcode])
	q.Logger.Debug("Round trip time", "rtt", rtt)

	return resp, nil
}
