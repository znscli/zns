package view

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestFormatTTL(t *testing.T) {
	t.Run("1 hour", func(t *testing.T) {
		ttl := formatTTL(3600)
		expected := "01h00m00s"
		assert.Equal(t, expected, ttl)
	})

	t.Run("3 minutes 42 seconds", func(t *testing.T) {
		ttl := formatTTL(222)
		expected := "03m42s"
		assert.Equal(t, expected, ttl)
	})

	t.Run("59 seconds", func(t *testing.T) {
		ttl := formatTTL(59)
		expected := "59s"
		assert.Equal(t, expected, ttl)
	})

	t.Run("0 seconds", func(t *testing.T) {
		ttl := formatTTL(0)
		expected := "00s"
		assert.Equal(t, expected, ttl)
	})
}

func TestFormatRecordAsJSON(t *testing.T) {
	t.Run("A record", func(t *testing.T) {
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

		json := formatRecordAsJSON(domain, record)

		assert.Contains(t, json, "@domain")
		assert.Contains(t, json, "@type")
		assert.Contains(t, json, "@ttl")
		assert.Contains(t, json, "@record")

		assert.Equal(t, domain, json["@domain"])
		assert.Equal(t, "A", json["@type"])
		assert.Equal(t, "03m42s", json["@ttl"])
		assert.Equal(t, "127.0.0.1", json["@record"])
	})

	t.Run("CNAME record", func(t *testing.T) {
		domain := "example.com"
		record := &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    500,
			},
			Target: fmt.Sprintf("%s.", domain),
		}

		json := formatRecordAsJSON(domain, record)

		assert.Contains(t, json, "@domain")
		assert.Contains(t, json, "@type")
		assert.Contains(t, json, "@ttl")
		assert.Contains(t, json, "@record")

		assert.Equal(t, domain, json["@domain"])
		assert.Equal(t, "CNAME", json["@type"])
		assert.Equal(t, "08m20s", json["@ttl"])
		assert.Equal(t, "example.com.", json["@record"])
	})

	t.Run("MX record", func(t *testing.T) {
		domain := "example.com"
		record := &dns.MX{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    500,
			},
			Preference: 10,
			Mx:         fmt.Sprintf("%s.", domain),
		}

		json := formatRecordAsJSON(domain, record)

		assert.Contains(t, json, "@domain")
		assert.Contains(t, json, "@type")
		assert.Contains(t, json, "@ttl")
		assert.Contains(t, json, "@record")
		assert.Contains(t, json, "@preference")

		assert.Equal(t, domain, json["@domain"])
		assert.Equal(t, "MX", json["@type"])
		assert.Equal(t, "08m20s", json["@ttl"])
		assert.Equal(t, "example.com.", json["@record"])
		assert.Equal(t, uint16(10), json["@preference"])
	})

	t.Run("SOA record", func(t *testing.T) {
		domain := "example.com"
		record := &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    500,
			},
			Ns:   fmt.Sprintf("%s.", domain),
			Mbox: "hostmaster.example.com.",
		}

		json := formatRecordAsJSON(domain, record)

		assert.Contains(t, json, "@domain")
		assert.Contains(t, json, "@type")
		assert.Contains(t, json, "@ttl")
		assert.Contains(t, json, "@primaryNameServer")
		assert.Contains(t, json, "@mbox")

		assert.Equal(t, domain, json["@domain"])
		assert.Equal(t, "SOA", json["@type"])
		assert.Equal(t, "08m20s", json["@ttl"])
		assert.Equal(t, "example.com.", json["@primaryNameServer"])
		assert.Equal(t, "hostmaster.example.com.", json["@mbox"])
	})

	t.Run("Unknown record type", func(t *testing.T) {
		domain := "example.com"
		record := &dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeSVCB,
				Class:  dns.ClassINET,
				Ttl:    500,
			},
			Priority: 10,
		}

		json := formatRecordAsJSON(domain, record)

		assert.Contains(t, json, "@domain")
		assert.Contains(t, json, "@type")
		assert.Contains(t, json, "@ttl")
		assert.Contains(t, json, "@record")

		assert.Contains(t, json["@record"], "Unknown record type")
	})
}

func TestFormatRecord(t *testing.T) {
	t.Run("A record", func(t *testing.T) {
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

		os.Setenv("NO_COLOR", "true") // Disable colors for easier testing

		r := formatRecord(domain, record)
		assert.Equal(t, "A\texample.com.\t03m42s\t127.0.0.1", r)
	})

	t.Run("CNAME record", func(t *testing.T) {
		domain := "example.com"
		record := &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    500,
			},
			Target: fmt.Sprintf("%s.", domain),
		}

		r := formatRecord(domain, record)
		assert.Equal(t, "CNAME\texample.com.\t08m20s\texample.com.", r)
	})

	t.Run("MX record", func(t *testing.T) {
		domain := "example.com"
		record := &dns.MX{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeMX,
				Class:  dns.ClassINET,
				Ttl:    500,
			},
			Preference: 10,
			Mx:         fmt.Sprintf("%s.", domain),
		}

		r := formatRecord(domain, record)
		assert.Equal(t, "MX\texample.com.\t08m20s\t10 example.com.", r)
	})

	t.Run("SOA record", func(t *testing.T) {
		domain := "example.com"
		record := &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    500,
			},
			Ns:   fmt.Sprintf("%s.", domain),
			Mbox: "hostmaster.example.com.",
		}

		r := formatRecord(domain, record)
		assert.Equal(t, "SOA\texample.com.\t08m20s\texample.com. hostmaster.example.com.", r)
	})

	t.Run("Unknown record type", func(t *testing.T) {
		domain := "example.com"
		record := &dns.SVCB{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeSVCB,
				Class:  dns.ClassINET,
				Ttl:    500,
			},
			Priority: 10,
		}

		r := formatRecord(domain, record)
		assert.Contains(t, r, "Unknown record type")
	})
}
