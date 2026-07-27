package view

import (
	"net"
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

// hdr returns a standard test header for the given record type, with a TTL of
// 500 seconds ("08m20s").
func hdr(rrtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: "example.com.", Rrtype: rrtype, Class: dns.ClassINET, Ttl: 500}
}

// mustRR parses a record in zone-file syntax, panicking on error. Used for
// record types that are easier to express in presentation format.
func mustRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}

// recordCases drives both TestFormatRecord and TestFormatRecordAsJSON: one
// case per supported record type, with the expected human-readable line and
// the expected JSON fields for the same record.
func recordCases() []struct {
	name   string
	record dns.RR
	human  string
	json   map[string]any
} {
	return []struct {
		name   string
		record dns.RR
		human  string
		json   map[string]any
	}{
		{
			name: "A",
			record: &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 222},
				A:   net.IPv4(127, 0, 0, 1),
			},
			human: "A\texample.com.\t03m42s\t127.0.0.1",
			json: map[string]any{
				"domain": "example.com", "type": "A", "ttl": "03m42s",
				"record": "127.0.0.1",
			},
		},
		{
			name: "AAAA",
			record: &dns.AAAA{
				Hdr:  hdr(dns.TypeAAAA),
				AAAA: net.ParseIP("2001:db8::1"),
			},
			human: "AAAA\texample.com.\t08m20s\t2001:db8::1",
			json: map[string]any{
				"domain": "example.com", "type": "AAAA", "ttl": "08m20s",
				"record": "2001:db8::1",
			},
		},
		{
			name: "AFSDB",
			record: &dns.AFSDB{
				Hdr:      hdr(dns.TypeAFSDB),
				Subtype:  1,
				Hostname: "afsdb.example.com.",
			},
			human: "AFSDB\texample.com.\t08m20s\t1 afsdb.example.com.",
			json: map[string]any{
				"domain": "example.com", "type": "AFSDB", "ttl": "08m20s",
				"subtype": uint16(1), "record": "afsdb.example.com.",
			},
		},
		{
			name: "CAA",
			record: &dns.CAA{
				Hdr:   hdr(dns.TypeCAA),
				Flag:  0,
				Tag:   "issue",
				Value: "letsencrypt.org",
			},
			human: "CAA\texample.com.\t08m20s\t0 issue letsencrypt.org",
			json: map[string]any{
				"domain": "example.com", "type": "CAA", "ttl": "08m20s",
				"flag": uint8(0), "tag": "issue", "record": "letsencrypt.org",
			},
		},
		{
			// CAA values are raw octets on the wire; control bytes must be
			// escaped so a malicious record cannot forge output lines.
			name: "CAA with control characters",
			record: &dns.CAA{
				Hdr:   hdr(dns.TypeCAA),
				Flag:  0,
				Tag:   "issue",
				Value: "evil\nTXT\tforged",
			},
			human: "CAA\texample.com.\t08m20s\t0 issue evil\\010TXT\\009forged",
			json: map[string]any{
				"domain": "example.com", "type": "CAA", "ttl": "08m20s",
				"flag": uint8(0), "tag": "issue", "record": "evil\\010TXT\\009forged",
			},
		},
		{
			name: "CDNSKEY",
			record: &dns.CDNSKEY{
				DNSKEY: dns.DNSKEY{
					Hdr:       hdr(dns.TypeCDNSKEY),
					Flags:     256,
					Protocol:  3,
					Algorithm: 13,
					PublicKey: "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
				},
			},
			human: "CDNSKEY\texample.com.\t08m20s\t256 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
			json: map[string]any{
				"domain": "example.com", "type": "CDNSKEY", "ttl": "08m20s",
				"flags": uint16(256), "protocol": uint8(3), "algorithm": uint8(13),
				"record": "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
			},
		},
		{
			// Wire-unpacked digests are lowercase hex; the zone-file
			// presentation (and dig) uppercase them.
			name: "CDS",
			record: &dns.CDS{
				DS: dns.DS{
					Hdr:        hdr(dns.TypeCDS),
					KeyTag:     20326,
					Algorithm:  8,
					DigestType: 2,
					Digest:     "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
				},
			},
			human: "CDS\texample.com.\t08m20s\t20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
			json: map[string]any{
				"domain": "example.com", "type": "CDS", "ttl": "08m20s",
				"keyTag": uint16(20326), "algorithm": uint8(8), "digestType": uint8(2),
				"record": "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
			},
		},
		{
			// CERT type and algorithm use presentation mnemonics, matching
			// CERT.String() and dig (1 -> PKIX, 8 -> RSASHA256).
			name: "CERT",
			record: &dns.CERT{
				Hdr:         hdr(dns.TypeCERT),
				Type:        1,
				KeyTag:      12345,
				Algorithm:   8,
				Certificate: "TUlJQ2NlcnRpZmljYXRl",
			},
			human: "CERT\texample.com.\t08m20s\tPKIX 12345 RSASHA256 TUlJQ2NlcnRpZmljYXRl",
			json: map[string]any{
				"domain": "example.com", "type": "CERT", "ttl": "08m20s",
				"certType": "PKIX", "keyTag": uint16(12345), "algorithm": "RSASHA256",
				"record": "TUlJQ2NlcnRpZmljYXRl",
			},
		},
		{
			name: "CERT with unknown type and algorithm falls back to numbers",
			record: &dns.CERT{
				Hdr:         hdr(dns.TypeCERT),
				Type:        250,
				KeyTag:      12345,
				Algorithm:   250,
				Certificate: "TUlJQ2NlcnRpZmljYXRl",
			},
			human: "CERT\texample.com.\t08m20s\t250 12345 250 TUlJQ2NlcnRpZmljYXRl",
			json: map[string]any{
				"domain": "example.com", "type": "CERT", "ttl": "08m20s",
				"certType": "250", "keyTag": uint16(12345), "algorithm": "250",
				"record": "TUlJQ2NlcnRpZmljYXRl",
			},
		},
		{
			name: "CNAME",
			record: &dns.CNAME{
				Hdr:    hdr(dns.TypeCNAME),
				Target: "example.com.",
			},
			human: "CNAME\texample.com.\t08m20s\texample.com.",
			json: map[string]any{
				"domain": "example.com", "type": "CNAME", "ttl": "08m20s",
				"record": "example.com.",
			},
		},
		{
			name: "DHCID",
			record: &dns.DHCID{
				Hdr:    hdr(dns.TypeDHCID),
				Digest: "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=",
			},
			human: "DHCID\texample.com.\t08m20s\tAAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=",
			json: map[string]any{
				"domain": "example.com", "type": "DHCID", "ttl": "08m20s",
				"record": "AAIBY2/AuCccgoJbsaxcQc9TUapptP69lOjxfNuVAA2kjEA=",
			},
		},
		{
			name: "DNAME",
			record: &dns.DNAME{
				Hdr:    hdr(dns.TypeDNAME),
				Target: "dname.example.com.",
			},
			human: "DNAME\texample.com.\t08m20s\tdname.example.com.",
			json: map[string]any{
				"domain": "example.com", "type": "DNAME", "ttl": "08m20s",
				"record": "dname.example.com.",
			},
		},
		{
			name: "DNSKEY",
			record: &dns.DNSKEY{
				Hdr:       hdr(dns.TypeDNSKEY),
				Flags:     257,
				Protocol:  3,
				Algorithm: 13,
				PublicKey: "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
			},
			human: "DNSKEY\texample.com.\t08m20s\t257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
			json: map[string]any{
				"domain": "example.com", "type": "DNSKEY", "ttl": "08m20s",
				"flags": uint16(257), "protocol": uint8(3), "algorithm": uint8(13),
				"record": "mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
			},
		},
		{
			name: "DS",
			record: &dns.DS{
				Hdr:        hdr(dns.TypeDS),
				KeyTag:     20326,
				Algorithm:  8,
				DigestType: 2,
				Digest:     "e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d",
			},
			human: "DS\texample.com.\t08m20s\t20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
			json: map[string]any{
				"domain": "example.com", "type": "DS", "ttl": "08m20s",
				"keyTag": uint16(20326), "algorithm": uint8(8), "digestType": uint8(2),
				"record": "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
			},
		},
		{
			name: "HINFO",
			record: &dns.HINFO{
				Hdr: hdr(dns.TypeHINFO),
				Cpu: "INTEL-64",
				Os:  "LINUX",
			},
			human: "HINFO\texample.com.\t08m20s\tINTEL-64 LINUX",
			json: map[string]any{
				"domain": "example.com", "type": "HINFO", "ttl": "08m20s",
				"cpu": "INTEL-64", "os": "LINUX",
			},
		},
		{
			name: "HTTPS",
			record: &dns.HTTPS{
				SVCB: dns.SVCB{
					Hdr:      hdr(dns.TypeHTTPS),
					Priority: 1,
					Target:   ".",
					Value: []dns.SVCBKeyValue{
						&dns.SVCBAlpn{Alpn: []string{"h2", "h3"}},
					},
				},
			},
			human: "HTTPS\texample.com.\t08m20s\t1 . alpn=\"h2,h3\"",
			json: map[string]any{
				"domain": "example.com", "type": "HTTPS", "ttl": "08m20s",
				"priority": uint16(1), "record": ".", "params": "alpn=\"h2,h3\"",
			},
		},
		{
			name: "KX",
			record: &dns.KX{
				Hdr:        hdr(dns.TypeKX),
				Preference: 10,
				Exchanger:  "kx.example.com.",
			},
			human: "KX\texample.com.\t08m20s\t10 kx.example.com.",
			json: map[string]any{
				"domain": "example.com", "type": "KX", "ttl": "08m20s",
				"preference": uint16(10), "record": "kx.example.com.",
			},
		},
		{
			name:   "LOC",
			record: mustRR("example.com. 500 IN LOC 37 46 30.000 N 122 23 30.000 W 10.00m 1m 10000m 10m"),
			human:  "LOC\texample.com.\t08m20s\t37 46 30.000 N 122 23 30.000 W 10m 1m 10000m 10m",
			json: map[string]any{
				"domain": "example.com", "type": "LOC", "ttl": "08m20s",
				"record": "37 46 30.000 N 122 23 30.000 W 10m 1m 10000m 10m",
			},
		},
		{
			name: "MX",
			record: &dns.MX{
				Hdr:        hdr(dns.TypeMX),
				Preference: 10,
				Mx:         "example.com.",
			},
			human: "MX\texample.com.\t08m20s\t10 example.com.",
			json: map[string]any{
				"domain": "example.com", "type": "MX", "ttl": "08m20s",
				"preference": uint16(10), "record": "example.com.",
			},
		},
		{
			name: "NAPTR",
			record: &dns.NAPTR{
				Hdr:         hdr(dns.TypeNAPTR),
				Order:       100,
				Preference:  10,
				Flags:       "S",
				Service:     "SIP+D2U",
				Regexp:      "!^.*$!sip:info@example.com!",
				Replacement: "_sip._udp.example.com.",
			},
			human: "NAPTR\texample.com.\t08m20s\t100 10 S SIP+D2U !^.*$!sip:info@example.com! _sip._udp.example.com.",
			json: map[string]any{
				"domain": "example.com", "type": "NAPTR", "ttl": "08m20s",
				"order": uint16(100), "preference": uint16(10), "flags": "S",
				"service": "SIP+D2U", "regexp": "!^.*$!sip:info@example.com!",
				"record": "_sip._udp.example.com.",
			},
		},
		{
			name: "NS",
			record: &dns.NS{
				Hdr: hdr(dns.TypeNS),
				Ns:  "ns1.example.com.",
			},
			human: "NS\texample.com.\t08m20s\tns1.example.com.",
			json: map[string]any{
				"domain": "example.com", "type": "NS", "ttl": "08m20s",
				"record": "ns1.example.com.",
			},
		},
		{
			name: "NSEC",
			record: &dns.NSEC{
				Hdr:        hdr(dns.TypeNSEC),
				NextDomain: "next.example.com.",
				TypeBitMap: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC},
			},
			human: "NSEC\texample.com.\t08m20s\tnext.example.com. A AAAA RRSIG NSEC",
			json: map[string]any{
				"domain": "example.com", "type": "NSEC", "ttl": "08m20s",
				"record": "next.example.com.", "types": "A AAAA RRSIG NSEC",
			},
		},
		{
			name: "NSEC3",
			record: &dns.NSEC3{
				Hdr:        hdr(dns.TypeNSEC3),
				Hash:       1,
				Flags:      1,
				Iterations: 5,
				Salt:       "aabbccdd",
				NextDomain: "39P91242OSLGGD1CCGEDIEKV3NPR3L6P",
				TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG},
			},
			human: "NSEC3\texample.com.\t08m20s\t1 1 5 AABBCCDD 39P91242OSLGGD1CCGEDIEKV3NPR3L6P A RRSIG",
			json: map[string]any{
				"domain": "example.com", "type": "NSEC3", "ttl": "08m20s",
				"hashAlgorithm": uint8(1), "flags": uint8(1), "iterations": uint16(5),
				"salt": "AABBCCDD", "record": "39P91242OSLGGD1CCGEDIEKV3NPR3L6P",
				"types": "A RRSIG",
			},
		},
		{
			name: "NSEC3PARAM",
			record: &dns.NSEC3PARAM{
				Hdr:        hdr(dns.TypeNSEC3PARAM),
				Hash:       1,
				Flags:      0,
				Iterations: 0,
				Salt:       "",
			},
			human: "NSEC3PARAM\texample.com.\t08m20s\t1 0 0 -",
			json: map[string]any{
				"domain": "example.com", "type": "NSEC3PARAM", "ttl": "08m20s",
				"hashAlgorithm": uint8(1), "flags": uint8(0), "iterations": uint16(0),
				"salt": "-",
			},
		},
		{
			name: "OPENPGPKEY",
			record: &dns.OPENPGPKEY{
				Hdr:       hdr(dns.TypeOPENPGPKEY),
				PublicKey: "mQINBFVHm5sBEADzP2sK3S09xSi",
			},
			human: "OPENPGPKEY\texample.com.\t08m20s\tmQINBFVHm5sBEADzP2sK3S09xSi",
			json: map[string]any{
				"domain": "example.com", "type": "OPENPGPKEY", "ttl": "08m20s",
				"record": "mQINBFVHm5sBEADzP2sK3S09xSi",
			},
		},
		{
			name: "PTR",
			record: &dns.PTR{
				Hdr: hdr(dns.TypePTR),
				Ptr: "ptr.example.com.",
			},
			human: "PTR\texample.com.\t08m20s\tptr.example.com.",
			json: map[string]any{
				"domain": "example.com", "type": "PTR", "ttl": "08m20s",
				"record": "ptr.example.com.",
			},
		},
		{
			name: "RP",
			record: &dns.RP{
				Hdr:  hdr(dns.TypeRP),
				Mbox: "admin.example.com.",
				Txt:  "txt.example.com.",
			},
			human: "RP\texample.com.\t08m20s\tadmin.example.com. txt.example.com.",
			json: map[string]any{
				"domain": "example.com", "type": "RP", "ttl": "08m20s",
				"mbox": "admin.example.com.", "txt": "txt.example.com.",
			},
		},
		{
			name: "RRSIG",
			record: &dns.RRSIG{
				Hdr:         hdr(dns.TypeRRSIG),
				TypeCovered: dns.TypeA,
				Algorithm:   13,
				Labels:      2,
				OrigTtl:     3600,
				Expiration:  1735689600, // 20250101000000
				Inception:   1704067200, // 20240101000000
				KeyTag:      34505,
				SignerName:  "example.com.",
				Signature:   "SGVsbG8=",
			},
			human: "RRSIG\texample.com.\t08m20s\tA 13 2 3600 20250101000000 20240101000000 34505 example.com. SGVsbG8=",
			json: map[string]any{
				"domain": "example.com", "type": "RRSIG", "ttl": "08m20s",
				"typeCovered": "A", "algorithm": uint8(13), "labels": uint8(2),
				"originalTtl": uint32(3600), "expiration": "20250101000000",
				"inception": "20240101000000", "keyTag": uint16(34505),
				"signerName": "example.com.", "record": "SGVsbG8=",
			},
		},
		{
			name: "SMIMEA",
			record: &dns.SMIMEA{
				Hdr:          hdr(dns.TypeSMIMEA),
				Usage:        3,
				Selector:     1,
				MatchingType: 1,
				Certificate:  "abc123def456",
			},
			human: "SMIMEA\texample.com.\t08m20s\t3 1 1 abc123def456",
			json: map[string]any{
				"domain": "example.com", "type": "SMIMEA", "ttl": "08m20s",
				"usage": uint8(3), "selector": uint8(1), "matchingType": uint8(1),
				"record": "abc123def456",
			},
		},
		{
			name: "SOA",
			record: &dns.SOA{
				Hdr:  hdr(dns.TypeSOA),
				Ns:   "example.com.",
				Mbox: "hostmaster.example.com.",
			},
			human: "SOA\texample.com.\t08m20s\texample.com. hostmaster.example.com.",
			json: map[string]any{
				"domain": "example.com", "type": "SOA", "ttl": "08m20s",
				"primaryNameServer": "example.com.", "mbox": "hostmaster.example.com.",
			},
		},
		{
			name: "SPF",
			record: &dns.SPF{
				Hdr: hdr(dns.TypeSPF),
				Txt: []string{"v=spf1 -all"},
			},
			human: "SPF\texample.com.\t08m20s\tv=spf1 -all",
			json: map[string]any{
				"domain": "example.com", "type": "SPF", "ttl": "08m20s",
				"record": "v=spf1 -all",
			},
		},
		{
			name: "SRV",
			record: &dns.SRV{
				Hdr:      hdr(dns.TypeSRV),
				Priority: 10,
				Weight:   5,
				Port:     443,
				Target:   "target.example.com.",
			},
			human: "SRV\texample.com.\t08m20s\t10 5 443 target.example.com.",
			json: map[string]any{
				"domain": "example.com", "type": "SRV", "ttl": "08m20s",
				"priority": uint16(10), "weight": uint16(5), "port": uint16(443),
				"record": "target.example.com.",
			},
		},
		{
			// Wire-unpacked fingerprints are lowercase hex; the zone-file
			// presentation (and dig) uppercase them.
			name: "SSHFP",
			record: &dns.SSHFP{
				Hdr:         hdr(dns.TypeSSHFP),
				Algorithm:   4,
				Type:        2,
				FingerPrint: "123456789abcdef67890123456789abcdef67890",
			},
			human: "SSHFP\texample.com.\t08m20s\t4 2 123456789ABCDEF67890123456789ABCDEF67890",
			json: map[string]any{
				"domain": "example.com", "type": "SSHFP", "ttl": "08m20s",
				"algorithm": uint8(4), "fingerprintType": uint8(2),
				"record": "123456789ABCDEF67890123456789ABCDEF67890",
			},
		},
		{
			name: "SVCB without params",
			record: &dns.SVCB{
				Hdr:      hdr(dns.TypeSVCB),
				Priority: 1,
				Target:   "svc.example.com.",
			},
			human: "SVCB\texample.com.\t08m20s\t1 svc.example.com.",
			json: map[string]any{
				"domain": "example.com", "type": "SVCB", "ttl": "08m20s",
				"priority": uint16(1), "record": "svc.example.com.",
			},
		},
		{
			name: "TLSA",
			record: &dns.TLSA{
				Hdr:          hdr(dns.TypeTLSA),
				Usage:        3,
				Selector:     1,
				MatchingType: 1,
				Certificate:  "6b76d034492b493e15a7376fccbf0d5551bc5c8f9fc1c8e7a7ce3b83cfa74f4b",
			},
			human: "TLSA\texample.com.\t08m20s\t3 1 1 6b76d034492b493e15a7376fccbf0d5551bc5c8f9fc1c8e7a7ce3b83cfa74f4b",
			json: map[string]any{
				"domain": "example.com", "type": "TLSA", "ttl": "08m20s",
				"usage": uint8(3), "selector": uint8(1), "matchingType": uint8(1),
				"record": "6b76d034492b493e15a7376fccbf0d5551bc5c8f9fc1c8e7a7ce3b83cfa74f4b",
			},
		},
		{
			name: "TXT",
			record: &dns.TXT{
				Hdr: hdr(dns.TypeTXT),
				Txt: []string{"Hello", "World"},
			},
			human: "TXT\texample.com.\t08m20s\tHello World",
			json: map[string]any{
				"domain": "example.com", "type": "TXT", "ttl": "08m20s",
				"record": "Hello World",
			},
		},
		{
			name: "URI",
			record: &dns.URI{
				Hdr:      hdr(dns.TypeURI),
				Priority: 10,
				Weight:   1,
				Target:   "https://example.com/path",
			},
			human: "URI\texample.com.\t08m20s\t10 1 https://example.com/path",
			json: map[string]any{
				"domain": "example.com", "type": "URI", "ttl": "08m20s",
				"priority": uint16(10), "weight": uint16(1),
				"record": "https://example.com/path",
			},
		},
		{
			// URI targets are raw octets on the wire; escape sequences (e.g.
			// ANSI) must not reach the terminal.
			name: "URI with control characters",
			record: &dns.URI{
				Hdr:      hdr(dns.TypeURI),
				Priority: 10,
				Weight:   1,
				Target:   "https://example.com/\x1b[31mred",
			},
			human: "URI\texample.com.\t08m20s\t10 1 https://example.com/\\027[31mred",
			json: map[string]any{
				"domain": "example.com", "type": "URI", "ttl": "08m20s",
				"priority": uint16(10), "weight": uint16(1),
				"record": "https://example.com/\\027[31mred",
			},
		},
		{
			// NULL data is arbitrary bytes and its String() does not escape,
			// so zns escapes it instead of using the generic fallback.
			name: "NULL",
			record: &dns.NULL{
				Hdr:  dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNULL, Class: dns.ClassINET, Ttl: 500},
				Data: "raw\nbytes\\here",
			},
			human: "NULL\texample.com.\t08m20s\traw\\010bytes\\\\here",
			json: map[string]any{
				"domain": "example.com", "type": "NULL", "ttl": "08m20s",
				"record": "raw\\010bytes\\\\here",
			},
		},
		{
			name: "ZONEMD",
			record: &dns.ZONEMD{
				Hdr:    hdr(dns.TypeZONEMD),
				Serial: 2021071219,
				Scheme: 1,
				Hash:   1,
				Digest: "febe3d4ce2ec2ffa4ba99d46cd69d6d29711e55217057bee7eb1a7b641a47ba7",
			},
			human: "ZONEMD\texample.com.\t08m20s\t2021071219 1 1 febe3d4ce2ec2ffa4ba99d46cd69d6d29711e55217057bee7eb1a7b641a47ba7",
			json: map[string]any{
				"domain": "example.com", "type": "ZONEMD", "ttl": "08m20s",
				"serial": uint32(2021071219), "scheme": uint8(1), "hashAlgorithm": uint8(1),
				"record": "febe3d4ce2ec2ffa4ba99d46cd69d6d29711e55217057bee7eb1a7b641a47ba7",
			},
		},
		{
			// Types without a dedicated formatter fall back to the record's
			// zone-file RDATA presentation.
			name:   "EUI48 via generic fallback",
			record: mustRR("example.com. 500 IN EUI48 11-22-33-44-55-66"),
			human:  "EUI48\texample.com.\t08m20s\t11-22-33-44-55-66",
			json: map[string]any{
				"domain": "example.com", "type": "EUI48", "ttl": "08m20s",
				"record": "11-22-33-44-55-66",
			},
		},
		{
			name:   "GPOS via generic fallback",
			record: mustRR("example.com. 500 IN GPOS -32.6882 116.8652 10.0"),
			human:  "GPOS\texample.com.\t08m20s\t-32.6882 116.8652 10.0",
			json: map[string]any{
				"domain": "example.com", "type": "GPOS", "ttl": "08m20s",
				"record": "-32.6882 116.8652 10.0",
			},
		},
		{
			// A record type unknown to the DNS library (RFC 3597) renders its
			// raw RDATA and a generated TYPExxx mnemonic.
			name: "unknown type via RFC 3597",
			record: &dns.RFC3597{
				Hdr:   dns.RR_Header{Name: "example.com.", Rrtype: 999, Class: dns.ClassINET, Ttl: 500},
				Rdata: "c0000201",
			},
			human: "TYPE999\texample.com.\t08m20s\t\\# 4 c0000201",
			json: map[string]any{
				"domain": "example.com", "type": "TYPE999", "ttl": "08m20s",
				"record": "\\# 4 c0000201",
			},
		},
	}
}

// TestFormatRecord_trailingDotDomain guards against rendering a double dot
// when the queried domain already ends with one (e.g. "zns com.").
func TestFormatRecord_trailingDotDomain(t *testing.T) {
	t.Setenv("NO_COLOR", "true")

	record := &dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 222},
		A:   net.IPv4(127, 0, 0, 1),
	}

	assert.Equal(t, "A\texample.com.\t03m42s\t127.0.0.1", formatRecord("example.com.", record))
}

func TestFormatRecord(t *testing.T) {
	t.Setenv("NO_COLOR", "true") // Disable colors for easier testing

	for _, tc := range recordCases() {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.human, formatRecord("example.com", tc.record))
		})
	}
}

func TestFormatRecordAsJSON(t *testing.T) {
	for _, tc := range recordCases() {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.json, formatRecordAsJSON("example.com", tc.record))
		})
	}
}
