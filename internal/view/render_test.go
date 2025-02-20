package view

import (
	"bytes"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/znscli/zns/internal/arguments"
	znsversion "github.com/znscli/zns/version"
)

// TestNewRenderer_human tests the NewRenderer function, which should return a HumanRenderer
// and bind provided io.Writer to the view's stream writer.
func TestNewRenderer_human(t *testing.T) {
	b := bytes.Buffer{}
	hv := NewRenderer(arguments.ViewHuman, NewView(&b))

	// Check that the view is a HumanRenderer
	humanRenderer, ok := hv.(*HumanRenderer)
	assert.True(t, ok, "Expected hv to be of type *HumanRenderer")

	assert.IsType(t, &HumanRenderer{}, humanRenderer)

	// Check that the view's stream writer is the same as the buffer
	assert.Equal(t, &b, humanRenderer.view.Stream.Writer)
}

// TestNewHumanRenderer should simply return a HumanRenderer.
func TestNewHumanRenderer(t *testing.T) {
	b := bytes.Buffer{}
	hv := NewView(&b)
	hr := NewHumanRenderer(hv)

	// Check that the view is a HumanRenderer
	assert.IsType(t, &HumanRenderer{}, hr)

	// Check that the view's stream writer is the same as the buffer
	assert.Equal(t, &b, hr.view.Stream.Writer)
}

func TestNewHumanRenderer_Render(t *testing.T) {
	t.Run("single record", func(t *testing.T) {
		b := bytes.Buffer{}
		v := NewView(&b)
		hr := NewHumanRenderer(v)

		t.Setenv("NO_COLOR", "1")

		domain := "example.com"
		record := &dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    222,
			},
			A: net.IPv4(127, 0, 0, 1),
		}

		hr.Render(domain, record)

		want := "A\texample.com.\t03m42s\t127.0.0.1\n"

		assert.Equal(t, want, b.String())
	})

	t.Run("multiple records", func(t *testing.T) {
		b := bytes.Buffer{}
		v := NewView(&b)
		hr := NewHumanRenderer(v)

		t.Setenv("NO_COLOR", "1")

		domain := "example.com"
		records := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    222,
				},
				A: net.IPv4(127, 0, 0, 1),
			},
			&dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    222,
				},
				AAAA: net.ParseIP("2001:db8::1"),
			},
		}

		for _, record := range records {
			hr.Render(domain, record)
		}

		want := "A\texample.com.\t03m42s\t127.0.0.1\n" +
			"AAAA\texample.com.\t03m42s\t2001:db8::1\n"

		assert.Equal(t, want, b.String())
	})
}

// TestNewRenderer_JSON tests the NewRenderer function, which should return a JSONRenderer
// and bind provided io.Writer to the view's stream writer.
func TestNewRenderer_JSON(t *testing.T) {
	b := bytes.Buffer{}
	jv := NewRenderer(arguments.ViewJSON, NewView(&b))

	// Check that the view is a JSONRenderer
	jsonRenderer, ok := jv.(*JSONRenderer)
	assert.True(t, ok, "Expected jv to be of type *JSONRenderer")

	// Check that the view's stream writer is the same as the buffer
	assert.Equal(t, &b, jsonRenderer.view.Stream.Writer)
}

// TestNewJSONRenderer should simply return a JSONRenderer.
func TestNewJSONRenderer(t *testing.T) {
	b := bytes.Buffer{}
	jv := NewJSONView(NewView(&b))
	jr := NewJSONRenderer(jv)

	// Check that the view is a JSONRenderer
	assert.IsType(t, &JSONRenderer{}, jr)

	// Check that the view's stream writer is the same as the buffer
	assert.Equal(t, &b, jr.view.Stream.Writer)
}

// TestNewJSONRenderer_Render tests the rendering of DNS records as JSON
// output. Verify that the output is in JSON log format, one message per line.
func TestNewJSONRenderer_Render(t *testing.T) {
	t.Run("single record", func(t *testing.T) {

		b := bytes.Buffer{}
		jv := NewJSONView(NewView(&b))
		jr := NewJSONRenderer(jv)

		domain := "example.com"
		record := &dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    222,
			},
			A: net.IPv4(127, 0, 0, 1),
		}

		jr.Render(domain, record)

		want := []map[string]interface{}{
			{
				"@domain":  domain,
				"@level":   "info",
				"@message": "Successful query",
				"@record":  "127.0.0.1",
				"@type":    "A",
				"@ttl":     "03m42s",
				"@version": znsversion.Version,
				"@view":    "json",
			},
		}

		testJSONViewOutputEqualsFull(t, b.String(), want)
	})

	t.Run("multiple records", func(t *testing.T) {

		b := bytes.Buffer{}
		jv := NewJSONView(NewView(&b))
		jr := NewJSONRenderer(jv)

		domain := "example.com"
		records := []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    222,
				},
				A: net.IPv4(127, 0, 0, 1),
			},
			&dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    222,
				},
				AAAA: net.ParseIP("2001:db8::1"),
			},
		}

		for _, record := range records {
			jr.Render(domain, record)
		}

		want := []map[string]interface{}{
			{
				"@domain":  domain,
				"@level":   "info",
				"@message": "Successful query",
				"@record":  "127.0.0.1",
				"@type":    "A",
				"@ttl":     "03m42s",
				"@version": znsversion.Version,
				"@view":    "json",
			},
			{
				"@domain":  domain,
				"@level":   "info",
				"@message": "Successful query",
				"@record":  "2001:db8::1",
				"@type":    "AAAA",
				"@ttl":     "03m42s",
				"@version": znsversion.Version,
				"@view":    "json",
			},
		}

		testJSONViewOutputEqualsFull(t, b.String(), want)
	})
}
