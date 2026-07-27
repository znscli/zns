package query

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
)

// DefaultQueryTypes are the record types queried when no specific query type
// is requested, ordered alphabetically so the rendered output is consistent.
var DefaultQueryTypes = []uint16{
	dns.TypeA,
	dns.TypeAAAA,
	dns.TypeAFSDB,
	dns.TypeCAA,
	dns.TypeCDNSKEY,
	dns.TypeCDS,
	dns.TypeCERT,
	dns.TypeCNAME,
	dns.TypeDHCID,
	dns.TypeDNAME,
	dns.TypeDNSKEY,
	dns.TypeDS,
	dns.TypeHINFO,
	dns.TypeHTTPS,
	dns.TypeKX,
	dns.TypeLOC,
	dns.TypeMX,
	dns.TypeNAPTR,
	dns.TypeNS,
	dns.TypeNSEC,
	dns.TypeNSEC3,
	dns.TypeNSEC3PARAM,
	dns.TypeOPENPGPKEY,
	dns.TypePTR,
	dns.TypeRP,
	dns.TypeRRSIG,
	dns.TypeSMIMEA,
	dns.TypeSOA,
	dns.TypeSPF,
	dns.TypeSRV,
	dns.TypeSSHFP,
	dns.TypeSVCB,
	dns.TypeTLSA,
	dns.TypeTXT,
	dns.TypeURI,
	dns.TypeZONEMD,
}

// metaQueryTypes are DNS types that do not represent queryable records, such
// as protocol-internal pseudo types and zone-transfer requests.
var metaQueryTypes = map[uint16]bool{
	dns.TypeNone:   true,
	dns.TypeNXNAME: true,
	dns.TypeOPT:    true,
	dns.TypeTKEY:   true,
	dns.TypeTSIG:   true,
	dns.TypeIXFR:   true,
	dns.TypeAXFR:   true,
	dns.TypeMAILB:  true,
	dns.TypeMAILA:  true,
}

// ParseQueryType resolves a case-insensitive record type name (e.g. "A",
// "https") to its DNS query type. Any record type known to the DNS library
// can be queried, except meta types such as OPT and AXFR.
func ParseQueryType(name string) (uint16, error) {
	qtype, ok := dns.StringToType[strings.ToUpper(name)]
	if !ok || metaQueryTypes[qtype] {
		return 0, fmt.Errorf("invalid query type: %s", name)
	}
	return qtype, nil
}

type DNSClient interface {
	Exchange(*dns.Msg, string) (*dns.Msg, time.Duration, error)
}

type QueryClient struct {
	Server string
	Client DNSClient
	// Fallback, if set, retries queries whose response came back truncated —
	// typically a TCP client, where the full answer fits.
	Fallback DNSClient
	// DNSSEC requests DNSSEC records (RRSIGs) by setting the DNSSEC OK (DO)
	// bit on queries.
	DNSSEC bool
	// Validate indicates that signatures are checked locally, which sets the
	// Checking Disabled (CD) bit: a validating resolver would otherwise
	// withhold bogus data as SERVFAIL, leaving nothing to inspect.
	Validate bool
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

// Query performs a single DNS query and returns the response.
func (q *QueryClient) Query(domain string, qtype uint16) (*dns.Msg, error) {
	return q.query(domain, qtype)
}

// query performs the DNS query and returns the response and any error encountered.
func (q *QueryClient) query(domain string, qtype uint16) (*dns.Msg, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	// Advertise a large EDNS0 UDP buffer so records that exceed 512 bytes
	// (e.g. DNSKEY or large TXT sets) are not truncated.
	msg.SetEdns0(4096, q.DNSSEC)
	msg.CheckingDisabled = q.Validate

	q.Debug("Querying DNS server", "server", q.Server, "domain", domain, "qtype", dns.TypeToString[qtype])

	resp, rtt, err := q.Client.Exchange(msg, q.Server)
	if err != nil {
		return nil, err
	}

	if resp.Truncated && q.Fallback != nil {
		q.Debug("Response truncated; retrying via fallback client", "server", q.Server, "domain", domain, "qtype", dns.TypeToString[qtype])
		if fresp, frtt, ferr := q.Fallback.Exchange(msg, q.Server); ferr == nil {
			resp, rtt = fresp, frtt
		} else {
			q.Debug("Fallback query failed; keeping the truncated response", "server", q.Server, "domain", domain, "err", ferr)
		}
	}

	q.Debug("Received DNS response", "server", q.Server, "domain", domain, "qtype", dns.TypeToString[qtype], "rcode", dns.RcodeToString[resp.Rcode])
	q.Debug("Round trip time", "rtt", rtt)

	return resp, nil
}
