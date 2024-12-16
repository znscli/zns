package view

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fatih/color"
	"github.com/miekg/dns"
)

// NewTabWriter initializes and returns a new tabwriter.Writer.
// ZNS uses this writer to format DNS records into a clear, human-readable table.
// See https://pkg.go.dev/text/tabwriter#Writer.Init for details.
func NewTabWriter(w io.Writer, debug bool) *tabwriter.Writer {
	flags := uint(0)
	if debug {
		flags = tabwriter.Debug
	}
	return tabwriter.NewWriter(
		w,
		0,   // Minwidth
		8,   // Tabwidth
		3,   // Padding
		' ', // Padchar
		flags,
	)
}

// formatTTL converts TTL to a more readable format (hours, minutes, seconds).
func formatTTL(ttl uint32) string {
	duration := time.Duration(ttl) * time.Second
	hours := int(duration.Hours())
	minutes := int(duration.Minutes()) % 60
	seconds := int(duration.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%02dh%02dm%02ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%02dm%02ds", minutes, seconds)
	}
	return fmt.Sprintf("%02ds", seconds)
}

// formatRecordAsJSON generates a map of DNS record fields for JSON rendering.
func formatRecordAsJSON(domain string, answer dns.RR) map[string]interface{} {
	m := make(map[string]interface{})
	m["@domain"] = domain
	m["@type"] = dns.TypeToString[answer.Header().Rrtype]
	m["@ttl"] = formatTTL(answer.Header().Ttl)

	// Add specific fields depending on the record type
	switch rec := answer.(type) {
	case *dns.A:
		m["@record"] = rec.A.String()
	case *dns.AAAA:
		m["@record"] = rec.AAAA.String()
	case *dns.CNAME:
		m["@record"] = rec.Target
	case *dns.MX:
		m["@preference"] = rec.Preference
		m["@record"] = rec.Mx
	case *dns.TXT:
		m["@record"] = strings.Join(rec.Txt, " ")
	case *dns.NS:
		m["@record"] = rec.Ns
	case *dns.SOA:
		m["@primaryNameServer"] = rec.Ns
		m["@mbox"] = rec.Mbox
	case *dns.PTR:
		m["@record"] = rec.Ptr
	default:
		m["@record"] = fmt.Sprintf("Unknown record type: %s", dns.TypeToString[answer.Header().Rrtype])
	}

	return m
}

// formatRecord generates a human-readable string representing a DNS record with colors.
func formatRecord(domainName string, answer dns.RR) string {
	recordType := color.HiYellowString(dns.TypeToString[answer.Header().Rrtype])
	formattedTTL := color.HiMagentaString(formatTTL(answer.Header().Ttl))

	switch rec := answer.(type) {
	case *dns.A:
		return fmt.Sprintf("%s\t%s.\t%s\t%s", recordType, color.HiBlueString(domainName), formattedTTL, color.HiWhiteString(rec.A.String()))
	case *dns.AAAA:
		return fmt.Sprintf("%s\t%s.\t%s\t%s", recordType, color.HiBlueString(domainName), formattedTTL, color.HiWhiteString(rec.AAAA.String()))
	case *dns.CNAME:
		return fmt.Sprintf("%s\t%s.\t%s\t%s", recordType, color.HiBlueString(domainName), formattedTTL, color.HiWhiteString(rec.Target))
	case *dns.MX:
		preference := color.HiRedString(strconv.FormatUint(uint64(rec.Preference), 10))
		return fmt.Sprintf("%s\t%s.\t%s\t%s %s", recordType, color.HiBlueString(domainName), formattedTTL, preference, color.HiWhiteString(rec.Mx))
	case *dns.TXT:
		txtJoined := strings.Join(rec.Txt, " ")
		return fmt.Sprintf("%s\t%s.\t%s\t%s", recordType, color.HiBlueString(domainName), formattedTTL, color.HiWhiteString(txtJoined))
	case *dns.NS:
		return fmt.Sprintf("%s\t%s.\t%s\t%s", recordType, color.HiBlueString(domainName), formattedTTL, color.HiWhiteString(rec.Ns))
	case *dns.SOA:
		primaryNameServer := color.HiRedString(rec.Ns)
		return fmt.Sprintf("%s\t%s.\t%s\t%s %s", recordType, color.HiBlueString(domainName), formattedTTL, primaryNameServer, color.HiWhiteString(rec.Mbox))
	case *dns.PTR:
		return fmt.Sprintf("%s\t%s.\t%s\t%s", recordType, color.HiBlueString(domainName), formattedTTL, color.HiWhiteString(rec.Ptr))
	default:
		return fmt.Sprintf(`
Unknown record type: %s

We encountered an unsupported DNS record type: %s. 

Please consider raising an issue on GitHub to add support for this record type.
https://github.com/znscli/zns/issues/new

Thank you for your contribution!
`, recordType, recordType)
	}
}
