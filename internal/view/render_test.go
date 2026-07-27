package view

import (
	"bytes"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	znsversion "github.com/znscli/zns/version"
)

// testARecord returns an A record for example.com with a TTL of 222 seconds
// ("03m42s").
func testARecord() *dns.A {
	return &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 222},
		A:   net.IPv4(127, 0, 0, 1),
	}
}

// testAAAARecord returns an AAAA record for example.com with a TTL of 222
// seconds ("03m42s").
func testAAAARecord() *dns.AAAA {
	return &dns.AAAA{
		Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 222},
		AAAA: net.ParseIP("2001:db8::1"),
	}
}

// decodeJSONLine unmarshals a single line of JSON output into a map.
func decodeJSONLine(t *testing.T, line string) map[string]any {
	t.Helper()
	var m map[string]any
	assert.NoError(t, json.Unmarshal([]byte(line), &m))
	return m
}

// popTimestamp asserts that the map holds a valid RFC 3339 timestamp and
// removes it, so the remaining fields can be compared deterministically.
func popTimestamp(t *testing.T, m map[string]any) {
	t.Helper()
	ts, ok := m["timestamp"].(string)
	assert.True(t, ok, "missing timestamp: %#v", m)
	_, err := time.Parse(time.RFC3339, ts)
	assert.NoError(t, err)
	delete(m, "timestamp")
}

func TestNewRenderer_human(t *testing.T) {
	r := NewRenderer(ViewHuman, &bytes.Buffer{})
	assert.IsType(t, &HumanRenderer{}, r)
}

func TestNewRenderer_JSON(t *testing.T) {
	r := NewRenderer(ViewJSON, &bytes.Buffer{})
	assert.IsType(t, &JSONRenderer{}, r)
}

func TestNewRenderer_unknownViewType(t *testing.T) {
	assert.Panics(t, func() {
		NewRenderer(ViewType(42), &bytes.Buffer{})
	})
}

func TestHumanRenderer_Render(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	b := bytes.Buffer{}
	NewHumanRenderer(&b).Render("example.com", testARecord())

	assert.Equal(t, "A\texample.com.\t03m42s\t127.0.0.1\n", b.String())
}

func TestHumanRenderer_Render_multipleRecords(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	b := bytes.Buffer{}
	hr := NewHumanRenderer(&b)
	hr.Render("example.com", testARecord())
	hr.Render("example.com", testAAAARecord())

	want := "A\texample.com.\t03m42s\t127.0.0.1\n" +
		"AAAA\texample.com.\t03m42s\t2001:db8::1\n"
	assert.Equal(t, want, b.String())
}

func TestJSONRenderer_Render(t *testing.T) {
	b := bytes.Buffer{}
	NewJSONRenderer(&b).Render("example.com", testARecord())

	m := decodeJSONLine(t, b.String())
	popTimestamp(t, m)
	assert.Equal(t, map[string]any{
		"domain":  "example.com",
		"level":   "info",
		"message": "Successful query",
		"record":  "127.0.0.1",
		"ttl":     "03m42s",
		"type":    "A",
		"version": znsversion.Version,
		"view":    "json",
	}, m)
}

func TestJSONRenderer_Render_numericFields(t *testing.T) {
	b := bytes.Buffer{}
	NewJSONRenderer(&b).Render("example.com", &dns.MX{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 222},
		Preference: 10,
		Mx:         "mail.example.com.",
	})

	m := decodeJSONLine(t, b.String())
	assert.Equal(t, float64(10), m["preference"])
	assert.Equal(t, "mail.example.com.", m["record"])
}

func TestJSONRenderer_Render_oneLinePerRecord(t *testing.T) {
	b := bytes.Buffer{}
	jr := NewJSONRenderer(&b)
	jr.Render("example.com", testARecord())
	jr.Render("example.com", testAAAARecord())

	lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	assert.Len(t, lines, 2)

	first := decodeJSONLine(t, lines[0])
	second := decodeJSONLine(t, lines[1])
	assert.Equal(t, "127.0.0.1", first["record"])
	assert.Equal(t, "2001:db8::1", second["record"])
}
