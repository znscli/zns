package dnssec

import (
	"crypto"
	"encoding/base64"
	"errors"
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

// TestValidate_bogusForeignDS guards against accepting a DS RRset owned by a
// different zone: an attacker can publish, in a zone they control, a DS whose
// digest covers a key they minted for the victim zone, and have their parent
// sign it for real.
func TestValidate_bogusForeignDS(t *testing.T) {
	z := newTestZone(t)

	// Attacker mints a key owned by "test." but publishes its DS under
	// "evil.test.", legitimately signed by the root.
	attackerKey, attackerPriv := zoneKey(t, "test.")
	foreignDS := attackerKey.ToDS(dns.SHA256)
	foreignDS.Hdr.Name = "evil.test."
	foreignDS.Hdr.Ttl = testTTL

	forged := []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "www.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: testTTL},
		A:   net.IPv4(198, 51, 100, 66),
	}}
	z.resolver["test./DS"] = msgWith(foreignDS, sign(t, z.rootKey, z.rootPriv, []dns.RR{foreignDS}))
	z.resolver["test./DNSKEY"] = msgWith(attackerKey, sign(t, attackerKey, attackerPriv, []dns.RR{attackerKey}))

	v := NewValidator(z.resolver, z.anchors)
	status, err := v.Validate(forged, []*dns.RRSIG{sign(t, attackerKey, attackerPriv, forged)})

	assert.Error(t, err)
	assert.NotEqual(t, StatusSecure, status)
}

// TestValidate_bogusSignerNotAncestor guards against a signer name that is
// only a string suffix of the owner name: "test." must not be able to sign
// records owned by "nottest.".
func TestValidate_bogusSignerNotAncestor(t *testing.T) {
	z := newTestZone(t)
	v := NewValidator(z.resolver, z.anchors)

	forged := []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "nottest.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: testTTL},
		A:   net.IPv4(198, 51, 100, 66),
	}}
	sig := sign(t, z.testKey, z.testPriv, forged)

	status, err := v.Validate(forged, []*dns.RRSIG{sig})

	assert.Error(t, err)
	assert.NotEqual(t, StatusSecure, status)
}

// TestValidate_bogusRevokedKey guards RFC 5011: a revoked key must not
// validate anything.
func TestValidate_bogusRevokedKey(t *testing.T) {
	z := newTestZone(t)

	revoked := *z.testKey
	revoked.Flags |= 128 // REVOKE

	rrset := []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "www.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: testTTL},
		A:   net.IPv4(192, 0, 2, 9),
	}}
	sig := sign(t, &revoked, z.testPriv, rrset)

	// The zone publishes only the revoked key, anchored by a matching DS.
	revokedDS := revoked.ToDS(dns.SHA256)
	revokedDS.Hdr.Ttl = testTTL
	z.resolver["test./DNSKEY"] = msgWith(&revoked, sign(t, &revoked, z.testPriv, []dns.RR{&revoked}))
	z.resolver["test./DS"] = msgWith(revokedDS, sign(t, z.rootKey, z.rootPriv, []dns.RR{revokedDS}))

	v := NewValidator(z.resolver, z.anchors)
	status, err := v.Validate(rrset, []*dns.RRSIG{sig})

	assert.Error(t, err)
	assert.NotEqual(t, StatusSecure, status)
}

// failOnceResolver fails the very first query, then behaves normally,
// simulating a single dropped UDP packet.
type failOnceResolver struct {
	inner  mapResolver
	failed bool
}

func (r *failOnceResolver) Query(domain string, qtype uint16) (*dns.Msg, error) {
	if !r.failed {
		r.failed = true
		return nil, errors.New("i/o timeout")
	}
	return r.inner.Query(domain, qtype)
}

// TestValidate_transientFailureNotCached guards that a dropped packet is
// reported as unknown rather than bogus, and is not cached: a retry of the
// same validation must succeed.
func TestValidate_transientFailureNotCached(t *testing.T) {
	z := newTestZone(t)
	resolver := &failOnceResolver{inner: z.resolver}
	v := NewValidator(resolver, z.anchors)

	status, err := v.Validate(z.aRRset, []*dns.RRSIG{z.aSig})
	assert.Error(t, err)
	assert.Equal(t, StatusUnknown, status)

	status, err = v.Validate(z.aRRset, []*dns.RRSIG{z.aSig})
	assert.NoError(t, err)
	assert.Equal(t, StatusSecure, status)
}

// TestValidate_secureWithDecoyKey guards that every DNSKEY matching the
// signature's key tag is tried, not just the first: key tags are a hint and
// may collide.
func TestValidate_secureWithDecoyKey(t *testing.T) {
	z := newTestZone(t)

	// A decoy key with the same key tag as the real one, listed first. The
	// key tag is an RFC 4034 checksum over the RDATA, so adjusting two
	// even-indexed public key bytes by +1/-1 preserves it.
	decoy := *z.testKey
	raw, err := base64.StdEncoding.DecodeString(z.testKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	raw[0]++
	raw[2]--
	decoy.PublicKey = base64.StdEncoding.EncodeToString(raw)
	assert.Equal(t, z.testKey.KeyTag(), decoy.KeyTag(), "decoy key must collide on key tag")

	keys := msgWith(&decoy, z.testKey, sign(t, z.testKey, z.testPriv, []dns.RR{&decoy, z.testKey}))
	z.resolver["test./DNSKEY"] = keys

	v := NewValidator(z.resolver, z.anchors)
	status, err := v.Validate(z.aRRset, []*dns.RRSIG{z.aSig})

	assert.NoError(t, err)
	assert.Equal(t, StatusSecure, status)
}

// TestValidate_secureWithExpiredSiblingSignature guards that a stale
// signature published alongside a fresh one does not shadow it.
func TestValidate_secureWithExpiredSiblingSignature(t *testing.T) {
	z := newTestZone(t)
	v := NewValidator(z.resolver, z.anchors)

	stale := signWithTimes(t, z.testKey, z.testPriv, z.aRRset,
		time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))

	status, err := v.Validate(z.aRRset, []*dns.RRSIG{stale, z.aSig})

	assert.NoError(t, err)
	assert.Equal(t, StatusSecure, status)
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
