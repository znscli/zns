package view

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/miekg/dns"
)

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

// formatRecordAsJSON generates a map of DNS record fields for JSON rendering
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

// formatRecord generates human-readable strings representing a DNS record with colors.
func formatRecord(domain string, answer dns.RR) []interface{} {
	recordType := color.HiYellowString(dns.TypeToString[answer.Header().Rrtype])
	formattedTTL := color.HiMagentaString(formatTTL(answer.Header().Ttl))

	switch rec := answer.(type) {
	case *dns.A:
		return []interface{}{recordType, color.HiBlueString(domain), formattedTTL, color.HiWhiteString(rec.A.String())}
	case *dns.AAAA:
		return []interface{}{recordType, color.HiBlueString(domain), formattedTTL, color.HiWhiteString(rec.AAAA.String())}
	case *dns.CNAME:
		return []interface{}{recordType, color.HiBlueString(domain), formattedTTL, color.HiWhiteString(rec.Target)}
	case *dns.MX:
		preference := color.HiRedString(strconv.FormatUint(uint64(rec.Preference), 10))
		return []interface{}{recordType, color.HiBlueString(domain), formattedTTL, preference, color.HiWhiteString(rec.Mx)}
	case *dns.TXT:
		txtJoined := strings.Join(rec.Txt, " ")
		return []interface{}{recordType, color.HiBlueString(domain), formattedTTL, color.HiWhiteString(txtJoined)}
	case *dns.NS:
		return []interface{}{recordType, color.HiBlueString(domain), formattedTTL, color.HiWhiteString(rec.Ns)}
	case *dns.SOA:
		primaryNameServer := color.HiRedString(rec.Ns)
		return []interface{}{recordType, color.HiBlueString(domain), formattedTTL, primaryNameServer, color.HiWhiteString(rec.Mbox)}
	case *dns.PTR:
		return []interface{}{recordType, color.HiBlueString(domain), formattedTTL, color.HiWhiteString(rec.Ptr)}
	default:
		return []interface{}{fmt.Sprintf(`
		Unknown record type: %s
		Please consider raising an issue on GitHub
		to add support for this record type.
		https://github.com/znscli/zns/issues/new
		Thank you for your contribution!
		`, recordType)}
	}
}
