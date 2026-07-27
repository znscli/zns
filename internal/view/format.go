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

// field is a single RDATA element of a DNS record: its JSON key and its raw
// value. Fields are ordered as they appear in the record's zone-file
// presentation, so both the human and JSON formatters derive from the same
// definition.
type field struct {
	key   string
	value any
}

// recordFields returns the RDATA fields of a DNS record in presentation
// order. Record types without a dedicated case fall back to a single @record
// field holding the record's zone-file RDATA presentation, so every record
// type the DNS library can parse is supported.
func recordFields(rr dns.RR) []field {
	switch rec := rr.(type) {
	case *dns.A:
		return []field{{"record", rec.A.String()}}
	case *dns.AAAA:
		return []field{{"record", rec.AAAA.String()}}
	case *dns.AFSDB:
		return []field{{"subtype", rec.Subtype}, {"record", rec.Hostname}}
	case *dns.CAA:
		return []field{{"flag", rec.Flag}, {"tag", rec.Tag}, {"record", escapeOctet(rec.Value)}}
	case *dns.CDNSKEY:
		return dnskeyFields(&rec.DNSKEY)
	case *dns.CDS:
		return dsFields(&rec.DS)
	case *dns.CERT:
		return []field{{"certType", certTypeString(rec.Type)}, {"keyTag", rec.KeyTag}, {"algorithm", algorithmString(rec.Algorithm)}, {"record", rec.Certificate}}
	case *dns.CNAME:
		return []field{{"record", rec.Target}}
	case *dns.DHCID:
		return []field{{"record", rec.Digest}}
	case *dns.DNAME:
		return []field{{"record", rec.Target}}
	case *dns.DNSKEY:
		return dnskeyFields(rec)
	case *dns.DS:
		return dsFields(rec)
	case *dns.HINFO:
		return []field{{"cpu", rec.Cpu}, {"os", rec.Os}}
	case *dns.HTTPS:
		return svcbFields(&rec.SVCB)
	case *dns.KX:
		return []field{{"preference", rec.Preference}, {"record", rec.Exchanger}}
	case *dns.MX:
		return []field{{"preference", rec.Preference}, {"record", rec.Mx}}
	case *dns.NAPTR:
		return []field{{"order", rec.Order}, {"preference", rec.Preference}, {"flags", rec.Flags}, {"service", rec.Service}, {"regexp", rec.Regexp}, {"record", rec.Replacement}}
	case *dns.NS:
		return []field{{"record", rec.Ns}}
	case *dns.NULL:
		return []field{{"record", escapeOctet(rec.Data)}}
	case *dns.NSEC:
		return []field{{"record", rec.NextDomain}, {"types", typesString(rec.TypeBitMap)}}
	case *dns.NSEC3:
		return []field{{"hashAlgorithm", rec.Hash}, {"flags", rec.Flags}, {"iterations", rec.Iterations}, {"salt", saltString(rec.Salt)}, {"record", rec.NextDomain}, {"types", typesString(rec.TypeBitMap)}}
	case *dns.NSEC3PARAM:
		return []field{{"hashAlgorithm", rec.Hash}, {"flags", rec.Flags}, {"iterations", rec.Iterations}, {"salt", saltString(rec.Salt)}}
	case *dns.OPENPGPKEY:
		return []field{{"record", rec.PublicKey}}
	case *dns.PTR:
		return []field{{"record", rec.Ptr}}
	case *dns.RP:
		return []field{{"mbox", rec.Mbox}, {"txt", rec.Txt}}
	case *dns.RRSIG:
		return []field{{"typeCovered", dns.Type(rec.TypeCovered).String()}, {"algorithm", rec.Algorithm}, {"labels", rec.Labels}, {"originalTtl", rec.OrigTtl}, {"expiration", dns.TimeToString(rec.Expiration)}, {"inception", dns.TimeToString(rec.Inception)}, {"keyTag", rec.KeyTag}, {"signerName", rec.SignerName}, {"record", rec.Signature}}
	case *dns.SMIMEA:
		return []field{{"usage", rec.Usage}, {"selector", rec.Selector}, {"matchingType", rec.MatchingType}, {"record", rec.Certificate}}
	case *dns.SOA:
		return []field{{"primaryNameServer", rec.Ns}, {"mbox", rec.Mbox}}
	case *dns.SPF:
		return []field{{"record", strings.Join(rec.Txt, " ")}}
	case *dns.SRV:
		return []field{{"priority", rec.Priority}, {"weight", rec.Weight}, {"port", rec.Port}, {"record", rec.Target}}
	case *dns.SSHFP:
		return []field{{"algorithm", rec.Algorithm}, {"fingerprintType", rec.Type}, {"record", strings.ToUpper(rec.FingerPrint)}}
	case *dns.SVCB:
		return svcbFields(rec)
	case *dns.TLSA:
		return []field{{"usage", rec.Usage}, {"selector", rec.Selector}, {"matchingType", rec.MatchingType}, {"record", rec.Certificate}}
	case *dns.TXT:
		return []field{{"record", strings.Join(rec.Txt, " ")}}
	case *dns.URI:
		return []field{{"priority", rec.Priority}, {"weight", rec.Weight}, {"record", escapeOctet(rec.Target)}}
	case *dns.ZONEMD:
		return []field{{"serial", rec.Serial}, {"scheme", rec.Scheme}, {"hashAlgorithm", rec.Hash}, {"record", rec.Digest}}
	default:
		return []field{{"record", rdataString(rr)}}
	}
}

func dnskeyFields(rec *dns.DNSKEY) []field {
	return []field{{"flags", rec.Flags}, {"protocol", rec.Protocol}, {"algorithm", rec.Algorithm}, {"record", rec.PublicKey}}
}

// dsFields uppercases the digest to match the zone-file presentation; records
// unpacked from the wire carry lowercase hex.
func dsFields(rec *dns.DS) []field {
	return []field{{"keyTag", rec.KeyTag}, {"algorithm", rec.Algorithm}, {"digestType", rec.DigestType}, {"record", strings.ToUpper(rec.Digest)}}
}

// certTypeString formats a CERT type as in its zone-file presentation, e.g.
// "PKIX", falling back to the raw number when unmapped.
func certTypeString(certType uint16) string {
	if s, ok := dns.CertTypeToString[certType]; ok {
		return s
	}
	return strconv.Itoa(int(certType))
}

// algorithmString formats a DNSSEC algorithm as in the CERT zone-file
// presentation, e.g. "RSASHA256", falling back to the raw number when
// unmapped.
func algorithmString(algorithm uint8) string {
	if s, ok := dns.AlgorithmToString[algorithm]; ok {
		return s
	}
	return strconv.Itoa(int(algorithm))
}

// escapeOctet escapes raw octet-encoded RDATA (CAA values, URI targets, NULL
// data) for safe single-line display, mirroring DNS presentation escaping:
// backslashes and non-printable bytes become \DDD sequences.
func escapeOctet(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			b.WriteString(`\\`)
		case c < ' ' || c > '~':
			fmt.Fprintf(&b, `\%03d`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func svcbFields(rec *dns.SVCB) []field {
	fields := []field{{"priority", rec.Priority}, {"record", rec.Target}}
	if len(rec.Value) > 0 {
		params := make([]string, len(rec.Value))
		for i, kv := range rec.Value {
			params[i] = kv.Key().String() + "=\"" + kv.String() + "\""
		}
		fields = append(fields, field{"params", strings.Join(params, " ")})
	}
	return fields
}

// typesString formats an NSEC/NSEC3 type bitmap as space-separated type names.
func typesString(bitmap []uint16) string {
	names := make([]string, len(bitmap))
	for i, t := range bitmap {
		names[i] = dns.Type(t).String()
	}
	return strings.Join(names, " ")
}

// saltString formats an NSEC3 salt as in its zone-file presentation, where an
// empty salt is written as "-".
func saltString(salt string) string {
	if salt == "" {
		return "-"
	}
	return strings.ToUpper(salt)
}

// rdataString returns the RDATA portion of a record's zone-file presentation,
// i.e. everything after the name, TTL, class, and type columns.
func rdataString(rr dns.RR) string {
	parts := strings.SplitN(rr.String(), "\t", 5)
	return parts[len(parts)-1]
}

// formatRecordAsJSON generates a map of DNS record fields for JSON rendering.
func formatRecordAsJSON(domain string, answer dns.RR) map[string]any {
	m := map[string]any{
		"domain": domain,
		"type":   dns.Type(answer.Header().Rrtype).String(),
		"ttl":    formatTTL(answer.Header().Ttl),
	}
	for _, f := range recordFields(answer) {
		m[f.key] = f.value
	}
	return m
}

// formatRecord generates a human-readable string representing a DNS record
// with colors: all fields but the last in red, the last in white. Optional
// extra columns are inserted before the value column: the value cell carries
// a varying number of color sequences per record type, which misleads the
// tabwriter's width bookkeeping, so it must stay the trailing column.
func formatRecord(domainName string, answer dns.RR, extraColumns ...string) string {
	fields := recordFields(answer)
	values := make([]string, len(fields))
	for i, f := range fields {
		s := fmt.Sprint(f.value)
		if i == len(fields)-1 {
			values[i] = color.HiWhiteString(s)
		} else {
			values[i] = color.HiRedString(s)
		}
	}

	columns := []string{
		color.HiYellowString(dns.Type(answer.Header().Rrtype).String()),
		color.HiBlueString(strings.TrimSuffix(domainName, ".")) + ".",
		color.HiMagentaString(formatTTL(answer.Header().Ttl)),
	}
	columns = append(columns, extraColumns...)
	columns = append(columns, strings.Join(values, " "))
	return strings.Join(columns, "\t")
}
