package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/znscli/zns/internal/query"
	"github.com/znscli/zns/internal/view"
)

// testServerAddr is the address of the test DNS server, bound to an
// ephemeral port so that concurrent test runs do not collide.
var testServerAddr string

func TestMain(m *testing.M) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}
	testServerAddr = conn.LocalAddr().String()

	server := &dns.Server{PacketConn: conn, Handler: dns.HandlerFunc(dnsHandler)}
	go func() {
		if err := server.ActivateAndServe(); err != nil {
			log.Fatalf("Failed to start DNS server: %v", err)
		}
	}()

	code := m.Run()
	_ = server.Shutdown()
	os.Exit(code)
}

func dnsHandler(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)

	// Simulate an A record response for "example.com"
	if len(r.Question) > 0 {
		q := r.Question[0]
		if q.Name == "example.com." && q.Qtype == dns.TypeA {
			// Example A record response
			a := &dns.A{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: net.ParseIP("93.184.216.34"),
			}
			msg.Answer = append(msg.Answer, a)
		}
		// Simulate a resolver failure, e.g. a DNSSEC validation error.
		if q.Name == "servfail.test." {
			msg.Rcode = dns.RcodeServerFailure
		}
		// Some resolvers fail individual types of an otherwise fine name.
		if q.Name == "example.com." && q.Qtype == dns.TypeNSEC3 {
			msg.Rcode = dns.RcodeServerFailure
		}
		// Simulate a name that does not exist.
		if q.Name == "nxdomain.test." {
			msg.Rcode = dns.RcodeNameError
		}
		// Simulate a PTR record for the reverse lookup of 192.0.2.1.
		if q.Name == "1.2.0.192.in-addr.arpa." && q.Qtype == dns.TypePTR {
			msg.Answer = append(msg.Answer, &dns.PTR{
				Hdr: dns.RR_Header{
					Name:   "1.2.0.192.in-addr.arpa.",
					Rrtype: dns.TypePTR,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Ptr: "ptr.example.com.",
			})
		}
		// Simulate a CNAME record response for "example.com"
		if q.Name == "example.com." && q.Qtype == dns.TypeCNAME {
			// Example CNAME record response
			cname := &dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   "example.com.",
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				Target: "example.org.",
			}
			msg.Answer = append(msg.Answer, cname)
		}
	}

	_ = w.WriteMsg(&msg)
}

func Test_Cmd(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--server", testServerAddr})

	err := rootCmd.Execute()

	assert.NoError(t, err)
}

func Test_Cmd_Error(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"--server", testServerAddr})

	err := rootCmd.Execute()

	assert.Error(t, err)
	assert.Equal(t, "error: domain name is required", err.Error())
}

func Test_Cmd_JSON(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	logFile := filepath.Join(t.TempDir(), "zns.json")
	t.Setenv("ZNS_LOG_FILE", logFile)

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--json", "--server", testServerAddr})

	err := rootCmd.Execute()
	assert.NoError(t, err)

	out, err := os.ReadFile(logFile)
	assert.NoError(t, err)

	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	assert.Len(t, lines, 2) // One JSON object per answered record: A and CNAME.

	var a map[string]any
	assert.NoError(t, json.Unmarshal([]byte(lines[0]), &a))
	assert.Equal(t, "example.com", a["domain"])
	assert.Equal(t, "A", a["type"])
	assert.Equal(t, "93.184.216.34", a["record"])
	assert.Equal(t, "01m00s", a["ttl"])
	assert.Equal(t, "info", a["level"])
	assert.Equal(t, "json", a["view"])

	var cname map[string]any
	assert.NoError(t, json.Unmarshal([]byte(lines[1]), &cname))
	assert.Equal(t, "CNAME", cname["type"])
	assert.Equal(t, "example.org.", cname["record"])
}

func Test_Cmd_QueryType(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--server", testServerAddr, "--query-type", "A"})

	err := rootCmd.Execute()

	assert.NoError(t, err)
}

// runToLogFile executes zns with the given args, capturing rendered output in
// a temp file, and returns the file content.
func runToLogFile(t *testing.T, args ...string) string {
	t.Helper()
	t.Setenv("NO_COLOR", "1")

	logFile := filepath.Join(t.TempDir(), "zns.log")
	t.Setenv("ZNS_LOG_FILE", logFile)

	rootCmd := NewRootCommand()
	rootCmd.SetArgs(append(args, "--server", testServerAddr))
	assert.NoError(t, rootCmd.Execute())

	out, err := os.ReadFile(logFile)
	assert.NoError(t, err)
	return string(out)
}

func Test_Cmd_MultipleQueryTypes_positional(t *testing.T) {
	out := runToLogFile(t, "example.com", "A", "CNAME")

	want := "A       example.com.   01m00s   93.184.216.34\n" +
		"CNAME   example.com.   01m00s   example.org.\n"
	assert.Equal(t, want, out)
}

func Test_Cmd_MultipleQueryTypes_commaFlag(t *testing.T) {
	out := runToLogFile(t, "example.com", "-q", "A,CNAME")

	want := "A       example.com.   01m00s   93.184.216.34\n" +
		"CNAME   example.com.   01m00s   example.org.\n"
	assert.Equal(t, want, out)
}

// Test_Cmd_MultipleQueryTypes_repeatedFlag also guards that results follow
// the requested type order rather than being re-sorted.
func Test_Cmd_MultipleQueryTypes_repeatedFlag(t *testing.T) {
	out := runToLogFile(t, "example.com", "-q", "CNAME", "-q", "A")

	want := "CNAME   example.com.   01m00s   example.org.\n" +
		"A       example.com.   01m00s   93.184.216.34\n"
	assert.Equal(t, want, out)
}

func Test_Cmd_MultipleQueryTypes_mixedFlagAndPositional(t *testing.T) {
	out := runToLogFile(t, "-q", "CNAME", "A", "example.com")

	want := "CNAME   example.com.   01m00s   example.org.\n" +
		"A       example.com.   01m00s   93.184.216.34\n"
	assert.Equal(t, want, out)
}

func Test_Cmd_MultipleQueryTypes_deduplicated(t *testing.T) {
	out := runToLogFile(t, "example.com", "A", "-q", "A")

	// A single rendered line: the duplicate A query is dropped.
	want := "A   example.com.   01m00s   93.184.216.34\n"
	assert.Equal(t, want, out)
}

// Test_Cmd_DNSSECValidate renders each record with a validation status
// column; the local test zone is unsigned, so the status is "insecure".
func Test_Cmd_DNSSECValidate(t *testing.T) {
	out := runToLogFile(t, "example.com", "-q", "A", "--dnssec-validate")

	want := "A   example.com.   01m00s   insecure   93.184.216.34\n"
	assert.Equal(t, want, out)
}

// Test_Cmd_Servfail_quietDuringDefaultSweep guards that the default sweep of
// every record type stays quiet when a resolver fails individual types: those
// failures are routine and would drown the results in warnings.
func Test_Cmd_Servfail_quietDuringDefaultSweep(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	var code int
	out := captureStderr(t, func() {
		code = run([]string{"example.com", "--server", testServerAddr})
	})

	assert.Equal(t, 0, code)
	assert.NotContains(t, out, "SERVFAIL")
}

// Test_Cmd_Servfail_allQueriesFailed guards that a name whose every query
// fails is reported as an error, not as an absence of records.
func Test_Cmd_Servfail_allQueriesFailed(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	var code int
	out := captureStderr(t, func() {
		code = run([]string{"servfail.test", "--server", testServerAddr})
	})

	assert.Equal(t, 1, code)
	assert.Contains(t, out, "servfail.test: all queries failed")
}

// Test_Cmd_ServfailWarning guards that a SERVFAIL for an explicitly requested
// type names the type on stderr, instead of silently rendering nothing.
func Test_Cmd_ServfailWarning(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	var code int
	out := captureStderr(t, func() {
		code = run([]string{"servfail.test", "-q", "A", "--server", testServerAddr})
	})

	assert.Equal(t, 1, code)
	assert.Contains(t, out, "warning: A query for servfail.test returned SERVFAIL")
}

// captureStderr runs fn with os.Stderr redirected and returns what was
// written to it.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()

	old := os.Stderr
	r, w, err := os.Pipe()
	assert.NoError(t, err)
	os.Stderr = w
	defer func() { os.Stderr = old }()

	fn()

	assert.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	assert.NoError(t, err)
	return string(out)
}

// Test_Execute_exitCode guards that failures are visible to the shell:
// zns must not report success when a query could not be made.
func Test_Execute_exitCode_error(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	var code int
	out := captureStderr(t, func() {
		code = run([]string{"example.com", "-q", "BOGUS", "--server", testServerAddr})
	})

	assert.Equal(t, 1, code)
	assert.Contains(t, out, "invalid query type: BOGUS")
}

func Test_Execute_exitCode_success(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	assert.Equal(t, 0, run([]string{"example.com", "-q", "A", "--server", testServerAddr}))
}

// Test_Execute_exitCode_nxdomain follows host(1): a name that does not exist
// is a failure for the caller.
func Test_Execute_exitCode_nxdomain(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	var code int
	out := captureStderr(t, func() {
		code = run([]string{"nxdomain.test", "-q", "A", "--server", testServerAddr})
	})

	assert.Equal(t, 1, code)
	assert.Contains(t, out, "nxdomain.test: no such domain")
}

// Test_Cmd_NoRecords tells the user why nothing was printed, rather than
// leaving them to guess.
func Test_Cmd_NoRecords(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	var code int
	out := captureStderr(t, func() {
		code = run([]string{"example.com", "-q", "MX", "--server", testServerAddr})
	})

	assert.Equal(t, 0, code) // The name exists; it just has no MX records.
	assert.Contains(t, out, "no MX records found for example.com")
}

func Test_Cmd_Short(t *testing.T) {
	out := runToLogFile(t, "example.com", "-q", "A", "--short")

	assert.Equal(t, "93.184.216.34\n", out)
}

func Test_Cmd_Short_rejectsJSON(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--short", "--json", "--server", testServerAddr})

	err := rootCmd.Execute()

	assert.Error(t, err)
	assert.Equal(t, "error: --short and --json cannot be combined", err.Error())
}

// Test_Cmd_ReverseLookup turns an address argument into a PTR query for the
// matching .arpa name.
func Test_Cmd_ReverseLookup(t *testing.T) {
	out := runToLogFile(t, "192.0.2.1")

	assert.Equal(t, "PTR   1.2.0.192.in-addr.arpa.   01m00s   ptr.example.com.\n", out)
}

func Test_Cmd_ReverseLookup_short(t *testing.T) {
	out := runToLogFile(t, "192.0.2.1", "--short")

	assert.Equal(t, "ptr.example.com.\n", out)
}

// Test_traceQueryTypes guards that a trace without an explicit record type
// walks the delegation once, rather than repeating it for every default type
// and hammering the root nameservers.
func Test_traceQueryTypes_defaultsToSingleWalk(t *testing.T) {
	assert.Equal(t, []uint16{dns.TypeA}, traceQueryTypes(query.DefaultQueryTypes))
}

func Test_traceQueryTypes_keepsRequestedTypes(t *testing.T) {
	requested := []uint16{dns.TypeMX, dns.TypeNS}

	assert.Equal(t, requested, traceQueryTypes(requested))
}

// A single requested type must be honoured, not replaced by the default.
func Test_traceQueryTypes_keepsSingleRequestedType(t *testing.T) {
	assert.Equal(t, []uint16{dns.TypeMX}, traceQueryTypes([]uint16{dns.TypeMX}))
}

// stubTracer returns canned delegation steps.
type stubTracer struct{ steps []query.TraceStep }

func (s stubTracer) Trace(string, uint16) ([]query.TraceStep, error) { return s.steps, nil }

func traceStep(zone string, msg *dns.Msg) query.TraceStep {
	return query.TraceStep{Server: "192.0.2.1:53", Zone: zone, Msg: msg}
}

// Test_renderTrace_rendersDelegationsThenAnswer renders the nameservers of
// each zone on the way down, then the records that answer the query.
func Test_renderTrace_rendersDelegationsThenAnswer(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	referral := new(dns.Msg)
	referral.Ns = []dns.RR{&dns.NS{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 60},
		Ns:  "ns1.example.com.",
	}}
	answer := new(dns.Msg)
	answer.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   net.ParseIP("93.184.216.34"),
	}}

	b := bytes.Buffer{}
	tracer := stubTracer{steps: []query.TraceStep{
		traceStep("example.com.", referral),
		traceStep("", answer),
	}}

	err := renderTrace(view.NewHumanRenderer(&b), tracer, "example.com", []uint16{dns.TypeA})

	assert.NoError(t, err)
	want := "NS\texample.com.\t01m00s\tns1.example.com.\n" +
		"A\texample.com.\t01m00s\t93.184.216.34\n"
	assert.Equal(t, want, b.String())
}

// Test_renderTrace_reportsEmptyResult guards that a trace ending without an
// answer says so, rather than printing nothing.
func Test_renderTrace_reportsEmptyResult(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	nxdomain := new(dns.Msg)
	nxdomain.Rcode = dns.RcodeNameError

	b := bytes.Buffer{}
	tracer := stubTracer{steps: []query.TraceStep{traceStep("", nxdomain)}}

	err := renderTrace(view.NewHumanRenderer(&b), tracer, "nxdomain.test", []uint16{dns.TypeA})

	assert.Error(t, err)
	assert.Equal(t, "error: nxdomain.test: no such domain", err.Error())
	assert.Empty(t, b.String())
}

func Test_Cmd_MultipleDomains_error(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "example.org", "--server", testServerAddr})

	err := rootCmd.Execute()

	assert.Error(t, err)
	assert.Equal(t, "error: multiple domain names provided: example.com, example.org", err.Error())
}

func Test_Cmd_InvalidQueryType(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--server", testServerAddr, "--query-type", "BOGUS"})

	err := rootCmd.Execute()

	assert.Error(t, err)
	assert.Equal(t, "error: invalid query type: BOGUS", err.Error())
}

func Test_Cmd_Debug(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--debug", "--server", testServerAddr, "--query-type", "A"})

	err := rootCmd.Execute()

	assert.NoError(t, err)
}

func Test_Cmd_LogFile(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	// A path only: the command creates the file itself. Holding an open
	// handle here would prevent the TempDir cleanup from deleting it on
	// Windows, where open files cannot be removed.
	logPath := filepath.Join(t.TempDir(), "zns.log")
	t.Setenv("ZNS_LOG_FILE", logPath)

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--server", testServerAddr})

	err := rootCmd.Execute()
	assert.NoError(t, err)

	assert.FileExists(t, logPath)

	logFile, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	// The file content is fully deterministic: only the two answered records
	// are written, in DefaultQueryTypes order.
	want := "A       example.com.   01m00s   93.184.216.34\n" +
		"CNAME   example.com.   01m00s   example.org.\n"
	assert.Equal(t, want, string(logFile))
}

func Test_Cmd_LogFile_Debug(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	// A path only: the command creates the file itself. Holding an open
	// handle here would prevent the TempDir cleanup from deleting it on
	// Windows, where open files cannot be removed.
	logPath := filepath.Join(t.TempDir(), "zns.log")
	t.Setenv("ZNS_LOG_FILE", logPath)

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--debug", "--server", testServerAddr})

	err := rootCmd.Execute()
	assert.NoError(t, err)

	assert.FileExists(t, logPath)

	logFile, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}

	assert.Contains(t, string(logFile), fmt.Sprintf("Querying DNS server: server=%s domain=example.com qtype=A", testServerAddr))
	assert.Contains(t, string(logFile), fmt.Sprintf("Querying DNS server: server=%s domain=example.com qtype=CNAME", testServerAddr))
	assert.Contains(t, string(logFile), fmt.Sprintf("Received DNS response: server=%s domain=example.com qtype=A rcode=NOERROR", testServerAddr))
	assert.Contains(t, string(logFile), fmt.Sprintf("Received DNS response: server=%s domain=example.com qtype=CNAME rcode=NOERROR", testServerAddr))
	assert.Contains(t, string(logFile), "A       |example.com.   |01m00s   |93.184.216.34")
	assert.Contains(t, string(logFile), "CNAME   |example.com.   |01m00s   |example.org.")
}

func TestEnsureDNSAddress(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"127.0.0.1", "127.0.0.1:53"},
		{"127.0.0.1:5353", "127.0.0.1:5353"},
		{"2001:558:feed::1", "[2001:558:feed::1]:53"},
		{"[2001:558:feed::1]:53", "[2001:558:feed::1]:53"},
		{"example.com", "example.com:53"},
		{"example.com:5353", "example.com:5353"},
		{"::ffff:1.1.1.1", "[::ffff:1.1.1.1]:53"},
		{"[::1]", "[::1]:53"},
		{"fe80::1%en0", "[fe80::1%en0]:53"},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("input=%s", tc.input), func(t *testing.T) {
			result := EnsureDNSAddress(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}
