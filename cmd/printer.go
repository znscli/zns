package cmd

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/miekg/dns"
)

// formatRecord generates a correctly tabbed string representing a DNS record.
func formatRecord(domainName string, answer dns.RR) string {
	domainColored := color.HiBlueString(domainName)

	recordType := dns.TypeToString[answer.Header().Rrtype]
	formattedTTL := color.HiMagentaString(formatTTL(answer.Header().Ttl))

	switch rec := answer.(type) {
	case *dns.A:
		return formatARecord(recordType, domainColored, formattedTTL, rec)

	case *dns.AAAA:
		return formatAAAARecord(recordType, domainColored, formattedTTL, rec)

	case *dns.CNAME:
		return formatCNAMERecord(recordType, domainColored, formattedTTL, rec)

	case *dns.MX:
		return formatMXRecord(recordType, domainColored, formattedTTL, rec)

	case *dns.TXT:
		return formatTXTRecord(recordType, domainColored, formattedTTL, rec)

	case *dns.NS:
		return formatNSRecord(recordType, domainColored, formattedTTL, rec)

	case *dns.SOA:
		return formatSOARecord(recordType, domainColored, formattedTTL, rec)

	case *dns.PTR:
		return formatPTRRecord(recordType, domainColored, formattedTTL, rec)

	default:
		return fmt.Sprintf("Unknown record type: %s", recordType)
	}
}

func formatARecord(queryType, domain, ttl string, rec *dns.A) string {
	return fmt.Sprintf("%s\t%s.\t%s\t%s", color.HiYellowString(queryType), domain, ttl, color.HiWhiteString(rec.A.String()))
}

func formatAAAARecord(queryType, domain, ttl string, rec *dns.AAAA) string {
	return fmt.Sprintf("%s\t%s.\t%s\t%s", color.HiYellowString(queryType), domain, ttl, color.HiWhiteString(rec.AAAA.String()))
}

func formatCNAMERecord(queryType, domain, ttl string, rec *dns.CNAME) string {
	return fmt.Sprintf("%s\t%s.\t%s\t%s", color.HiYellowString(queryType), domain, ttl, color.HiWhiteString(rec.Target))
}

func formatMXRecord(queryType, domain, ttl string, rec *dns.MX) string {
	preference := color.HiRedString(strconv.FormatUint(uint64(rec.Preference), 10))
	return fmt.Sprintf("%s\t%s.\t%s\t%s %s", color.HiYellowString(queryType), domain, ttl, preference, color.HiWhiteString(rec.Mx))
}

func formatTXTRecord(queryType, domain, ttl string, rec *dns.TXT) string {
	txtJoined := strings.Join(rec.Txt, " ")
	return fmt.Sprintf("%s\t%s.\t%s\t%s", color.HiYellowString(queryType), domain, ttl, color.HiWhiteString(txtJoined))
}

func formatNSRecord(queryType, domain, ttl string, rec *dns.NS) string {
	return fmt.Sprintf("%s\t%s.\t%s\t%s", color.HiYellowString(queryType), domain, ttl, color.HiWhiteString(rec.Ns))
}

func formatSOARecord(queryType, domain, ttl string, rec *dns.SOA) string {
	primaryNameServer := color.HiRedString(rec.Ns)
	return fmt.Sprintf("%s\t%s.\t%s\t%s %s", color.HiYellowString(queryType), domain, ttl, primaryNameServer, rec.Mbox)
}

func formatPTRRecord(queryType, domain, ttl string, rec *dns.PTR) string {
	return fmt.Sprintf("%s\t%s.\t%s\t%s", color.HiYellowString(queryType), domain, ttl, color.HiWhiteString(rec.Ptr))
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
