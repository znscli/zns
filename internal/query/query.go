package query

import (
	"github.com/hashicorp/go-hclog"
	"github.com/miekg/dns"
	"os"
)

// Querier is an interface for querying DNS records
type Querier interface {
	Query(domain string, qtype uint16) (*dns.Msg, error)
}

// Query implements the Querier interface
type Query struct {
	Server string
	hclog.Logger
}

// NewQuerier creates a new Querier with the specified server
func NewQuerier(server string, logger hclog.Logger) Querier {
	if logger == nil {
		logger = hclog.New(&hclog.LoggerOptions{
			Name:  "zns",
			Level: hclog.LevelFromString(os.Getenv("ZNS_LOG_LEVEL")),
			Color: hclog.AutoColor,
            DisableTime: true,
		})
		logger.Warn("no logger provided, using default 'zns' logger")
	}
	return &Query{Server: server, Logger: logger}
}

// Query performs the DNS query and returns the response and any error encountered
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
