package query

import (
	"fmt"
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
	// ReceivedDomain stores the domain name extracted from the request.
	// This is used to verify that the correct domain name is passed to the underlying DNS client.
	ReceivedDomain string

	// QueryType stores the DNS query type (e.g., A, MX) extracted from the request.
	// This is used to verify that the correct query type is passed to the underlying DNS client.
	QueryType uint16
}

func (m *MockDNSClient) Exchange(req *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	// If the request contains a question, capture the domain name and query type.
	if len(req.Question) > 0 {
		m.ReceivedDomain = req.Question[0].Name
		m.QueryType = req.Question[0].Qtype
	}

	// Return a mock response with a fixed round-trip time and no error.
	return &dns.Msg{}, time.Microsecond * 42, nil
}

// MockDNSClientWithError is a mock DNS client used for testing purposes.
// It is used to override the Exchange method to return an error.
type MockDNSClientWithError struct{}

func (m *MockDNSClientWithError) Exchange(req *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	return &dns.Msg{}, time.Microsecond * 42, fmt.Errorf("it's always DNS")
}

func TestQueryClient_Query(t *testing.T) {
	// Use a null logger to suppress log output during testing.
	client := NewQueryClient("8.8.8.8", hclog.NewNullLogger())

	mockDNSClient := &MockDNSClient{}
	client.Client = mockDNSClient

	_, err := client.query("example.com", dns.TypeA)

	assert.Nil(t, err)

	assert.Equal(t, "example.com.", mockDNSClient.ReceivedDomain)
	assert.Equal(t, dns.TypeA, mockDNSClient.QueryType)
}

func TestQueryClient_Query_Domain(t *testing.T) {
	// Use a null logger to suppress log output during testing.
	client := NewQueryClient("1.1.1.1", hclog.NewNullLogger())

	mockDNSClient := &MockDNSClient{}
	client.Client = mockDNSClient

	_, err := client.query("abc.xyz", dns.TypeA)

	assert.Nil(t, err)

	assert.Equal(t, "abc.xyz.", mockDNSClient.ReceivedDomain)
}

func TestQueryClient_Query_QueryType(t *testing.T) {
	// Use a null logger to suppress log output during testing.
	client := NewQueryClient("1.1.1.1", hclog.NewNullLogger())

	mockDNSClient := &MockDNSClient{}
	client.Client = mockDNSClient

	_, err := client.query("abc.xyz", dns.TypeCNAME)

	assert.Nil(t, err)

	assert.Equal(t, dns.TypeCNAME, mockDNSClient.QueryType)
}

func TestQueryClient_Query_Error(t *testing.T) {
	// Use a null logger to suppress log output during testing.
	client := NewQueryClient("8.8.8.8", hclog.NewNullLogger())

	mockDNSClientWithError := &MockDNSClientWithError{}
	client.Client = mockDNSClientWithError

	_, err := client.query("example.com", dns.TypeA)

	assert.NotNil(t, err)
	assert.Equal(t, "it's always DNS", err.Error())
}

func TestQueryClient_MultiQuery(t *testing.T) {
	// Use a null logger to suppress log output during testing.
	client := NewQueryClient("8.8.8.8", hclog.NewNullLogger())

	mockDNSClient := &MockDNSClient{}
	client.Client = mockDNSClient

	resp, err := client.MultiQuery("example.com", []uint16{dns.TypeA, dns.TypeMX})

	assert.Nil(t, err)

	assert.Equal(t, "example.com.", mockDNSClient.ReceivedDomain)
	assert.Equal(t, 2, len(resp))
}

func TestQueryClient_MultiQuery_Domain(t *testing.T) {
	// Use a null logger to suppress log output during testing.
	client := NewQueryClient("1.1.1.1", hclog.NewNullLogger())

	mockDNSClient := &MockDNSClient{}
	client.Client = mockDNSClient

	_, err := client.MultiQuery("abc.xyz", []uint16{dns.TypeA, dns.TypeMX})

	assert.Nil(t, err)

	assert.Equal(t, "abc.xyz.", mockDNSClient.ReceivedDomain)
}

func TestQueryClient_MultiQuery_Error(t *testing.T) {
	// Use a null logger to suppress log output during testing.
	client := NewQueryClient("1.1.1.1", hclog.NewNullLogger())

	mockDNSClientWithError := &MockDNSClientWithError{}
	client.Client = mockDNSClientWithError

	_, err := client.MultiQuery("1", []uint16{dns.TypeA, dns.TypeMX})

	assert.NotNil(t, err)
}

func TestQueryClient_MultiQuery_TypeAssert_MultiError(t *testing.T) {
	// Use a null logger to suppress log output during testing.
	client := NewQueryClient("1.1.1.1", hclog.NewNullLogger())

	mockDNSClientWithError := &MockDNSClientWithError{}
	client.Client = mockDNSClientWithError

	_, err := client.MultiQuery("1", []uint16{dns.TypeA, dns.TypeMX})

	assert.NotNil(t, err)

	// Because MultiQuery returns a multierror.Error, we assert that the error is of that type.
	assert.IsType(t, &multierror.Error{}, err)

	// We also assert that the error contains two errors, as we are querying two different types.
	assert.Equal(t, 2, len(err.(*multierror.Error).Errors))

	// Similarly, we can assert the error messages.
	for _, e := range err.(*multierror.Error).Errors {
		assert.NotNil(t, e)
		assert.Equal(t, "it's always DNS", e.Error())
	}
}
