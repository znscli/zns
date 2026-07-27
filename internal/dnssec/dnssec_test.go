package dnssec

import (
	"crypto"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

const testTTL = 300

// mapResolver serves canned responses keyed by "name/TYPE".
type mapResolver map[string]*dns.Msg

func (m mapResolver) Query(domain string, qtype uint16) (*dns.Msg, error) {
	if msg, ok := m[domain+"/"+dns.TypeToString[qtype]]; ok {
		return msg, nil
	}
	return new(dns.Msg), nil
}

func msgWith(rrs ...dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.Answer = rrs
	return msg
}

// zoneKey generates an ECDSA P-256 key-signing key for a zone.
func zoneKey(t *testing.T, zone string) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	key := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: testTTL},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ECDSAP256SHA256,
	}
	priv, err := key.Generate(256)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("generated key is not a crypto.Signer: %T", priv)
	}
	return key, signer
}

// signWithTimes signs an RRset with an explicit validity window.
func signWithTimes(t *testing.T, key *dns.DNSKEY, priv crypto.Signer, rrset []dns.RR, inception, expiration time.Time) *dns.RRSIG {
	t.Helper()
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: rrset[0].Header().Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: testTTL},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   key.Algorithm,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
		OrigTtl:     testTTL,
		Expiration:  uint32(expiration.Unix()),
		Inception:   uint32(inception.Unix()),
		KeyTag:      key.KeyTag(),
		SignerName:  key.Hdr.Name,
	}
	if err := sig.Sign(priv, rrset); err != nil {
		t.Fatal(err)
	}
	return sig
}

func sign(t *testing.T, key *dns.DNSKEY, priv crypto.Signer, rrset []dns.RR) *dns.RRSIG {
	t.Helper()
	now := time.Now()
	return signWithTimes(t, key, priv, rrset, now.Add(-time.Hour), now.Add(time.Hour))
}

// testZone is a signed chain: root (".") delegates to "test." which holds an
// A record at "www.test.". The trust anchor is the root key's DS.
type testZone struct {
	resolver mapResolver
	anchors  []*dns.DS
	aRRset   []dns.RR
	aSig     *dns.RRSIG

	rootKey  *dns.DNSKEY
	rootPriv crypto.Signer
	testKey  *dns.DNSKEY
	testPriv crypto.Signer
}

func newTestZone(t *testing.T) *testZone {
	t.Helper()

	rootKey, rootPriv := zoneKey(t, ".")
	testKey, testPriv := zoneKey(t, "test.")

	testDS := testKey.ToDS(dns.SHA256)
	testDS.Hdr.Ttl = testTTL

	aRecord := &dns.A{
		Hdr: dns.RR_Header{Name: "www.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: testTTL},
		A:   net.IPv4(192, 0, 2, 1),
	}
	aRRset := []dns.RR{aRecord}

	z := &testZone{
		resolver: mapResolver{
			"./DNSKEY":     msgWith(rootKey, sign(t, rootKey, rootPriv, []dns.RR{rootKey})),
			"test./DNSKEY": msgWith(testKey, sign(t, testKey, testPriv, []dns.RR{testKey})),
			"test./DS":     msgWith(testDS, sign(t, rootKey, rootPriv, []dns.RR{testDS})),
		},
		anchors:  []*dns.DS{rootKey.ToDS(dns.SHA256)},
		aRRset:   aRRset,
		aSig:     sign(t, testKey, testPriv, aRRset),
		rootKey:  rootKey,
		rootPriv: rootPriv,
		testKey:  testKey,
		testPriv: testPriv,
	}
	return z
}

func TestValidate_secure(t *testing.T) {
	z := newTestZone(t)
	v := NewValidator(z.resolver, z.anchors)

	status, err := v.Validate(z.aRRset, []*dns.RRSIG{z.aSig})

	assert.NoError(t, err)
	assert.Equal(t, StatusSecure, status)
}

func TestValidate_bogusTamperedRecord(t *testing.T) {
	z := newTestZone(t)
	v := NewValidator(z.resolver, z.anchors)

	// Tamper with the record after signing.
	tampered, ok := z.aRRset[0].(*dns.A)
	assert.True(t, ok)
	tampered.A = net.IPv4(198, 51, 100, 66)

	status, err := v.Validate(z.aRRset, []*dns.RRSIG{z.aSig})

	assert.Error(t, err)
	assert.Equal(t, StatusBogus, status)
}

func TestValidate_bogusExpiredSignature(t *testing.T) {
	z := newTestZone(t)
	v := NewValidator(z.resolver, z.anchors)

	expired := signWithTimes(t, z.testKey, z.testPriv, z.aRRset,
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	status, err := v.Validate(z.aRRset, []*dns.RRSIG{expired})

	assert.Error(t, err)
	assert.Equal(t, StatusBogus, status)
}

func TestValidate_insecureUnsignedRRset(t *testing.T) {
	z := newTestZone(t)
	v := NewValidator(z.resolver, z.anchors)

	status, err := v.Validate(z.aRRset, nil)

	assert.NoError(t, err)
	assert.Equal(t, StatusInsecure, status)
}

func TestValidate_insecureUnsignedDelegation(t *testing.T) {
	z := newTestZone(t)
	delete(z.resolver, "test./DS")
	v := NewValidator(z.resolver, z.anchors)

	status, err := v.Validate(z.aRRset, []*dns.RRSIG{z.aSig})

	assert.Error(t, err)
	assert.Equal(t, StatusInsecure, status)
}

func TestValidate_bogusWrongTrustAnchor(t *testing.T) {
	z := newTestZone(t)
	otherKey, _ := zoneKey(t, ".")
	v := NewValidator(z.resolver, []*dns.DS{otherKey.ToDS(dns.SHA256)})

	status, err := v.Validate(z.aRRset, []*dns.RRSIG{z.aSig})

	assert.Error(t, err)
	assert.Equal(t, StatusBogus, status)
}

func TestValidate_bogusMissingDNSKEY(t *testing.T) {
	z := newTestZone(t)
	delete(z.resolver, "test./DNSKEY")
	v := NewValidator(z.resolver, z.anchors)

	status, err := v.Validate(z.aRRset, []*dns.RRSIG{z.aSig})

	assert.Error(t, err)
	assert.Equal(t, StatusBogus, status)
}

func TestValidate_emptyRRset(t *testing.T) {
	z := newTestZone(t)
	v := NewValidator(z.resolver, z.anchors)

	status, err := v.Validate(nil, nil)

	assert.NoError(t, err)
	assert.Equal(t, StatusInsecure, status)
}

// TestRootAnchors guards the built-in IANA trust anchors: root key tags
// 20326 (KSK-2017) and 38696 (KSK-2024).
func TestRootAnchors(t *testing.T) {
	anchors := RootAnchors()

	assert.Len(t, anchors, 2)
	assert.Equal(t, uint16(20326), anchors[0].KeyTag)
	assert.Equal(t, uint16(38696), anchors[1].KeyTag)
	for _, anchor := range anchors {
		assert.Equal(t, ".", anchor.Hdr.Name)
		assert.Equal(t, uint8(8), anchor.Algorithm)  // RSASHA256
		assert.Equal(t, uint8(2), anchor.DigestType) // SHA-256
	}
}
