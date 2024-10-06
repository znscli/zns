package query

import (
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"os"
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
	QueryTypes(domain string, qtypes []uint16) ([]*dns.Msg, error)
}

// Query implements the Querier interface.
type Query struct {
	Server string
	hclog.Logger
}

// NewQuerier creates a new Querier with the specified server.
func NewQuerier(server string, logger hclog.Logger) Querier {
	if logger == nil {
		logger = hclog.New(&hclog.LoggerOptions{
			Name:        "zns",
			Level:       hclog.LevelFromString(os.Getenv("ZNS_LOG_LEVEL")),
			Color:       hclog.AutoColor,
			DisableTime: true,
		})
	}
	return &Query{Server: server, Logger: logger}
}

// QueryTypes performs DNS queries for multiple types concurrently.
func (q *Query) QueryTypes(domain string, qtypes []uint16) ([]*dns.Msg, error) {
	var errors *multierror.Error
	var wg sync.WaitGroup
	messages := make([]*dns.Msg, len(qtypes))

	for i, qtype := range qtypes {
		wg.Add(1)
		go func(i int, qtype uint16) {
			defer wg.Done()
			msg, err := q.Query(domain, qtype)
			messages[i] = msg
			errors = multierror.Append(errors, err)
		}(i, qtype)
	}

	wg.Wait()

	return messages, errors.ErrorOrNil()
}

// Query performs the DNS query and returns the response and any error encountered.
func (q *Query) Query(domain string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)

	client := new(dns.Client)
	resp, _, err := client.Exchange(msg, q.Server)
	if err != nil {
		return nil, err
	}

	return resp, nil
}
