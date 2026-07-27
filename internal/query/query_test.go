package query

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

// MockDNSClient is a mock DNS client used for testing purposes.
// It is used to override the Exchange method to capture and introspect the DNS query.
type MockDNSClient struct {
	// mu guards the captured fields; MultiQuery calls Exchange concurrently.
	mu sync.Mutex

	// ReceivedDomain stores the domain name extracted from the request.
	// This is used to verify that the correct domain name is passed to the underlying DNS client.
	ReceivedDomain string

	// QueryType stores the DNS query type (e.g., A, MX) extracted from the request.
	// This is used to verify that the correct query type is passed to the underlying DNS client.
	QueryType uint16

	// ReceivedUDPSize stores the EDNS0 UDP buffer size advertised in the request.
	ReceivedUDPSize uint16
}

func (m *MockDNSClient) Exchange(req *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	// If the request contains a question, capture the domain name and query type.
	if len(req.Question) > 0 {
		m.mu.Lock()
		m.ReceivedDomain = req.Question[0].Name
		m.QueryType = req.Question[0].Qtype
		if opt := req.IsEdns0(); opt != nil {
			m.ReceivedUDPSize = opt.UDPSize()
		}
		m.mu.Unlock()
	}

	// Return a mock response with a fixed round-trip time and no error.
	return &dns.Msg{}, time.Microsecond * 42, nil
}

// MockTruncatedDNSClient always returns a truncated response, as a UDP server
// does for answers that exceed the advertised buffer size.
type MockTruncatedDNSClient struct{}

func (m *MockTruncatedDNSClient) Exchange(req *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	return &dns.Msg{MsgHdr: dns.MsgHdr{Truncated: true}}, time.Microsecond * 42, nil
}

// MockDNSClientWithError is a mock DNS client used for testing purposes.
// It is used to override the Exchange method to return an error.
type MockDNSClientWithError struct{}

func (m *MockDNSClientWithError) Exchange(req *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	return &dns.Msg{}, time.Microsecond * 42, fmt.Errorf("it's always DNS")
}

func TestDefaultQueryTypes(t *testing.T) {
	want := []uint16{
		dns.TypeA, dns.TypeAAAA, dns.TypeAFSDB, dns.TypeCAA,
		dns.TypeCDNSKEY, dns.TypeCDS, dns.TypeCERT, dns.TypeCNAME,
		dns.TypeDHCID, dns.TypeDNAME, dns.TypeDNSKEY, dns.TypeDS,
		dns.TypeHINFO, dns.TypeHTTPS, dns.TypeKX, dns.TypeLOC,
		dns.TypeMX, dns.TypeNAPTR, dns.TypeNS, dns.TypeNSEC,
		dns.TypeNSEC3, dns.TypeNSEC3PARAM, dns.TypeOPENPGPKEY, dns.TypePTR,
		dns.TypeRP, dns.TypeRRSIG, dns.TypeSMIMEA, dns.TypeSOA,
		dns.TypeSPF, dns.TypeSRV, dns.TypeSSHFP, dns.TypeSVCB,
		dns.TypeTLSA, dns.TypeTXT, dns.TypeURI, dns.TypeZONEMD,
	}
	assert.Equal(t, want, DefaultQueryTypes)
}

// TestDefaultQueryTypes_sortedByName guards the alphabetical ordering that
// the rendered output relies on, since MultiQuery preserves input order.
func TestDefaultQueryTypes_sortedByName(t *testing.T) {
	names := make([]string, len(DefaultQueryTypes))
	for i, qtype := range DefaultQueryTypes {
		names[i] = dns.TypeToString[qtype]
	}
	assert.True(t, sort.StringsAreSorted(names), "DefaultQueryTypes must be sorted by type name, got: %v", names)
}

func TestParseQueryType(t *testing.T) {
	qtype, err := ParseQueryType("A")
	assert.NoError(t, err)
	assert.Equal(t, dns.TypeA, qtype)
}

func TestParseQueryType_lowercase(t *testing.T) {
	qtype, err := ParseQueryType("https")
	assert.NoError(t, err)
	assert.Equal(t, dns.TypeHTTPS, qtype)
}

func TestParseQueryType_any(t *testing.T) {
	qtype, err := ParseQueryType("ANY")
	assert.NoError(t, err)
	assert.Equal(t, dns.TypeANY, qtype)
}

func TestParseQueryType_unknown(t *testing.T) {
	_, err := ParseQueryType("BOGUS")
	assert.EqualError(t, err, "invalid query type: BOGUS")
}

func TestParseQueryType_metaTypesRejected(t *testing.T) {
	for _, name := range []string{"None", "NXNAME", "OPT", "TKEY", "TSIG", "IXFR", "AXFR", "MAILB", "MAILA"} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseQueryType(name)
			assert.EqualError(t, err, "invalid query type: "+name)
		})
	}
}

func TestQueryClient_Query(t *testing.T) {
	mockDNSClient := &MockDNSClient{}
	client := NewQueryClient("8.8.8.8", mockDNSClient, hclog.NewNullLogger())

	_, err := client.query("example.com", dns.TypeA)

	assert.NoError(t, err)
	assert.Equal(t, "example.com.", mockDNSClient.ReceivedDomain)
	assert.Equal(t, dns.TypeA, mockDNSClient.QueryType)
}

func TestQueryClient_Query_Domain(t *testing.T) {
	mockDNSClient := &MockDNSClient{}
	client := NewQueryClient("8.8.8.8", mockDNSClient, hclog.NewNullLogger())

	_, err := client.query("example.com", dns.TypeA)

	assert.NoError(t, err)
	assert.Equal(t, "example.com.", mockDNSClient.ReceivedDomain)
}

func TestQueryClient_Query_QueryType(t *testing.T) {
	mockDNSClient := &MockDNSClient{}
	client := NewQueryClient("8.8.8.8", mockDNSClient, hclog.NewNullLogger())

	_, err := client.query("example.com", dns.TypeCNAME)

	assert.NoError(t, err)
	assert.Equal(t, dns.TypeCNAME, mockDNSClient.QueryType)
}

// TestQueryClient_Query_setsEDNS0 guards that queries advertise a large EDNS0
// UDP buffer, so records that exceed 512 bytes (e.g. DNSKEY, TXT sets) are not
// truncated.
func TestQueryClient_Query_setsEDNS0(t *testing.T) {
	mockDNSClient := &MockDNSClient{}
	client := NewQueryClient("8.8.8.8", mockDNSClient, hclog.NewNullLogger())

	_, err := client.query("example.com", dns.TypeTXT)

	assert.NoError(t, err)
	assert.Equal(t, uint16(4096), mockDNSClient.ReceivedUDPSize)
}

// TestQueryClient_Query_truncatedRetriesOverFallback guards that a truncated
// response is retried via the fallback (TCP) client, so large record sets are
// fully retrieved.
func TestQueryClient_Query_truncatedRetriesOverFallback(t *testing.T) {
	fallback := &MockDNSClient{}
	client := NewQueryClient("8.8.8.8", &MockTruncatedDNSClient{}, hclog.NewNullLogger())
	client.Fallback = fallback

	resp, err := client.query("example.com", dns.TypeTXT)

	assert.NoError(t, err)
	assert.Equal(t, "example.com.", fallback.ReceivedDomain)
	assert.False(t, resp.Truncated)
}

func TestQueryClient_Query_truncatedWithoutFallback(t *testing.T) {
	client := NewQueryClient("8.8.8.8", &MockTruncatedDNSClient{}, hclog.NewNullLogger())

	resp, err := client.query("example.com", dns.TypeTXT)

	assert.NoError(t, err)
	assert.True(t, resp.Truncated)
}

func TestQueryClient_Query_Error(t *testing.T) {
	mockDNSClientWithError := &MockDNSClientWithError{}
	client := NewQueryClient("8.8.8.8", mockDNSClientWithError, hclog.NewNullLogger())

	_, err := client.query("example.com", dns.TypeA)

	assert.Error(t, err)
	assert.Equal(t, "it's always DNS", err.Error())
}

func TestQueryClient_MultiQuery(t *testing.T) {
	mockDNSClient := &MockDNSClient{}
	client := NewQueryClient("8.8.8.8", mockDNSClient, hclog.NewNullLogger())

	resp, err := client.MultiQuery("example.com", []uint16{dns.TypeA, dns.TypeMX})

	assert.NoError(t, err)
	assert.Equal(t, "example.com.", mockDNSClient.ReceivedDomain)
	assert.Len(t, resp, 2)
}

func TestQueryClient_MultiQuery_Domain(t *testing.T) {
	mockDNSClient := &MockDNSClient{}
	client := NewQueryClient("8.8.8.8", mockDNSClient, hclog.NewNullLogger())

	_, err := client.MultiQuery("example.com", []uint16{dns.TypeA, dns.TypeMX})

	assert.NoError(t, err)
	assert.Equal(t, "example.com.", mockDNSClient.ReceivedDomain)
}

func TestQueryClient_MultiQuery_Error(t *testing.T) {
	mockDNSClientWithError := &MockDNSClientWithError{}
	client := NewQueryClient("8.8.8.8", mockDNSClientWithError, hclog.NewNullLogger())

	_, err := client.MultiQuery("example.com", []uint16{dns.TypeA, dns.TypeMX})

	assert.Error(t, err)
}

func TestQueryClient_MultiQuery_TypeAssert_MultiError(t *testing.T) {
	mockDNSClientWithError := &MockDNSClientWithError{}
	client := NewQueryClient("8.8.8.8", mockDNSClientWithError, hclog.NewNullLogger())

	_, err := client.MultiQuery("example.com", []uint16{dns.TypeA, dns.TypeMX})

	assert.Error(t, err)
	assert.IsType(t, &multierror.Error{}, err)

	if err, ok := err.(*multierror.Error); ok {
		assert.Len(t, err.Errors, 2)
		for _, e := range err.Errors {
			assert.Equal(t, "it's always DNS", e.Error())
		}
	}
}
