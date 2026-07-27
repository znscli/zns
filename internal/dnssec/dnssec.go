// Package dnssec validates DNS records against the DNSSEC chain of trust:
// RRset signatures (RRSIG) are verified with the signer zone's keys (DNSKEY),
// and each zone's keys are verified against the delegation signer (DS)
// records of its parent, up to the root zone trust anchors.
//
// The validator covers positive answers only; authenticated denial of
// existence (NSEC/NSEC3 proofs) is not implemented.
package dnssec

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Status is the DNSSEC validation result for an RRset.
type Status string

const (
	// StatusSecure means the RRset validated against the chain of trust up to
	// a trust anchor.
	StatusSecure Status = "secure"
	// StatusInsecure means the RRset is not covered by DNSSEC: it carries no
	// signatures, or its zone is an unsigned delegation.
	StatusInsecure Status = "insecure"
	// StatusBogus means validation was attempted but failed.
	StatusBogus Status = "bogus"
)

// Resolver performs the DNS queries the validator needs. Responses must
// include DNSSEC records, i.e. queries must set the DNSSEC OK (DO) bit.
type Resolver interface {
	Query(domain string, qtype uint16) (*dns.Msg, error)
}

// errInsecureDelegation marks a break in the chain of trust that means a zone
// is unsigned rather than tampered with.
var errInsecureDelegation = errors.New("unsigned delegation")

// Validator validates RRsets against the DNSSEC chain of trust, caching
// per-zone results across validations.
type Validator struct {
	resolver Resolver
	anchors  []*dns.DS
	zones    map[string]error
	keys     map[string]*keyResponse
}

// keyResponse holds a zone's DNSKEY RRset and the signatures covering it.
type keyResponse struct {
	keys []*dns.DNSKEY
	sigs []*dns.RRSIG
}

// NewValidator returns a Validator that resolves through r and trusts the
// given root DS anchors, typically RootAnchors().
func NewValidator(r Resolver, anchors []*dns.DS) *Validator {
	return &Validator{
		resolver: r,
		anchors:  anchors,
		zones:    make(map[string]error),
		keys:     make(map[string]*keyResponse),
	}
}

// RootAnchors returns the IANA root zone trust anchors.
// See https://www.iana.org/dnssec/files.
func RootAnchors() []*dns.DS {
	return []*dns.DS{
		mustDS(". 0 IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"), // KSK-2017
		mustDS(". 0 IN DS 38696 8 2 683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"), // KSK-2024
	}
}

func mustDS(s string) *dns.DS {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	ds, ok := rr.(*dns.DS)
	if !ok {
		panic("not a DS record: " + s)
	}
	return ds
}

// Validate checks one RRset together with its covering signatures against the
// chain of trust. The returned error explains a non-secure status.
func (v *Validator) Validate(rrset []dns.RR, sigs []*dns.RRSIG) (Status, error) {
	if len(rrset) == 0 {
		return StatusInsecure, nil
	}

	covering := make([]*dns.RRSIG, 0, len(sigs))
	for _, sig := range sigs {
		if sig.TypeCovered == rrset[0].Header().Rrtype {
			covering = append(covering, sig)
		}
	}
	if len(covering) == 0 {
		return StatusInsecure, nil
	}

	var lastErr error
	for _, sig := range covering {
		if err := v.verify(rrset, sig); err != nil {
			lastErr = err
			continue
		}
		return StatusSecure, nil
	}
	if errors.Is(lastErr, errInsecureDelegation) {
		return StatusInsecure, lastErr
	}
	return StatusBogus, lastErr
}

// verify checks a single signature over the RRset and the signer zone's chain
// of trust.
func (v *Validator) verify(rrset []dns.RR, sig *dns.RRSIG) error {
	if !sig.ValidityPeriod(time.Now()) {
		return fmt.Errorf("signature for %s is outside its validity period", sig.Hdr.Name)
	}

	keys, err := v.zoneKeys(sig.SignerName)
	if err != nil {
		return err
	}
	key := keys.key(sig.KeyTag, sig.Algorithm)
	if key == nil {
		return fmt.Errorf("zone %s has no DNSKEY with key tag %d", sig.SignerName, sig.KeyTag)
	}
	if err := sig.Verify(key, rrset); err != nil {
		return fmt.Errorf("signature verification for %s failed: %v", sig.Hdr.Name, err)
	}
	return v.secureZone(sig.SignerName)
}

func (r *keyResponse) key(keyTag uint16, algorithm uint8) *dns.DNSKEY {
	for _, key := range r.keys {
		if key.KeyTag() == keyTag && key.Algorithm == algorithm {
			return key
		}
	}
	return nil
}

// zoneKeys fetches (and caches) a zone's DNSKEY RRset with its signatures.
func (v *Validator) zoneKeys(zone string) (*keyResponse, error) {
	zone = strings.ToLower(dns.Fqdn(zone))
	if keys, ok := v.keys[zone]; ok {
		return keys, nil
	}

	msg, err := v.resolver.Query(zone, dns.TypeDNSKEY)
	if err != nil {
		return nil, err
	}
	keys := &keyResponse{}
	for _, rr := range msg.Answer {
		switch rec := rr.(type) {
		case *dns.DNSKEY:
			keys.keys = append(keys.keys, rec)
		case *dns.RRSIG:
			if rec.TypeCovered == dns.TypeDNSKEY {
				keys.sigs = append(keys.sigs, rec)
			}
		}
	}
	v.keys[zone] = keys
	return keys, nil
}

// secureZone verifies (and caches) a zone's position in the chain of trust.
func (v *Validator) secureZone(zone string) error {
	zone = strings.ToLower(dns.Fqdn(zone))
	if err, ok := v.zones[zone]; ok {
		return err
	}
	// Guard against delegation loops while this zone is being checked.
	v.zones[zone] = fmt.Errorf("chain of trust loop at zone %s", zone)

	err := v.checkZone(zone)
	v.zones[zone] = err
	return err
}

// checkZone verifies that one of the zone's DNSKEYs matches a DS record in
// the parent zone (or a trust anchor at the root), and that this key signs
// the zone's DNSKEY RRset.
func (v *Validator) checkZone(zone string) error {
	keys, err := v.zoneKeys(zone)
	if err != nil {
		return err
	}
	if len(keys.keys) == 0 {
		return fmt.Errorf("no DNSKEY records for zone %s", zone)
	}

	dsset, err := v.dsRecords(zone)
	if err != nil {
		return err
	}
	if len(dsset) == 0 {
		return fmt.Errorf("%w: no DS records for zone %s", errInsecureDelegation, zone)
	}

	rrset := make([]dns.RR, len(keys.keys))
	for i, key := range keys.keys {
		rrset[i] = key
	}

	lastErr := fmt.Errorf("no DNSKEY of zone %s matches its DS records", zone)
	for _, ds := range dsset {
		for _, key := range keys.keys {
			if key.KeyTag() != ds.KeyTag || key.Algorithm != ds.Algorithm {
				continue
			}
			computed := key.ToDS(ds.DigestType)
			if computed == nil || !strings.EqualFold(computed.Digest, ds.Digest) {
				lastErr = fmt.Errorf("DNSKEY %d of zone %s does not match its DS digest", ds.KeyTag, zone)
				continue
			}
			// The anchored key must sign the zone's DNSKEY RRset.
			if err := verifyRRsetWithKey(rrset, keys.sigs, key); err != nil {
				lastErr = err
				continue
			}
			return nil
		}
	}
	return lastErr
}

// verifyRRsetWithKey verifies an RRset against the signature made by the
// given key.
func verifyRRsetWithKey(rrset []dns.RR, sigs []*dns.RRSIG, key *dns.DNSKEY) error {
	for _, sig := range sigs {
		if sig.KeyTag != key.KeyTag() {
			continue
		}
		if !sig.ValidityPeriod(time.Now()) {
			return fmt.Errorf("signature for %s is outside its validity period", sig.Hdr.Name)
		}
		if err := sig.Verify(key, rrset); err != nil {
			return fmt.Errorf("signature verification for %s failed: %v", sig.Hdr.Name, err)
		}
		return nil
	}
	return fmt.Errorf("RRset of %s is not signed by key %d", key.Hdr.Name, key.KeyTag())
}

// dsRecords returns the validated DS RRset for a zone: the trust anchors at
// the root, or the DS records from the parent zone otherwise, themselves
// validated through the parent's chain of trust.
func (v *Validator) dsRecords(zone string) ([]*dns.DS, error) {
	if zone == "." {
		return v.anchors, nil
	}

	msg, err := v.resolver.Query(zone, dns.TypeDS)
	if err != nil {
		return nil, err
	}
	var dsset []*dns.DS
	var sigs []*dns.RRSIG
	var rrset []dns.RR
	for _, rr := range msg.Answer {
		switch rec := rr.(type) {
		case *dns.DS:
			dsset = append(dsset, rec)
			rrset = append(rrset, rec)
		case *dns.RRSIG:
			if rec.TypeCovered == dns.TypeDS {
				sigs = append(sigs, rec)
			}
		}
	}
	if len(dsset) == 0 {
		return nil, nil // No DS records: the caller reports an unsigned delegation.
	}

	// The DS RRset lives in the parent zone and must itself validate.
	var lastErr error
	for _, sig := range sigs {
		if err := v.verify(rrset, sig); err != nil {
			lastErr = err
			continue
		}
		return dsset, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("DS RRset for zone %s is unsigned", zone)
	}
	return nil, lastErr
}
