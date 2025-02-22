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
