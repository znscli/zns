package cmd

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

const (
	DNSServerPort = 53535
)

func TestMain(m *testing.M) {
	go startDNSServer()

	code := m.Run()
	os.Exit(code)
}

func startDNSServer() {
	dns.HandleFunc(".", dnsHandler)

	go func() {
		err := dns.ListenAndServe(fmt.Sprintf(":%d", DNSServerPort), "udp", nil)
		if err != nil {
			log.Fatalf("Failed to start DNS server: %v", err)
		}
	}()
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
	rootCmd.SetArgs([]string{"example.com", "--server", fmt.Sprintf("127.0.0.1:%d", DNSServerPort)})

	err := rootCmd.Execute()

	assert.NoError(t, err)
}

func Test_Cmd_Error(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"--server", fmt.Sprintf("127.0.0.1:%d", DNSServerPort)})

	err := rootCmd.Execute()

	assert.Error(t, err)
	assert.Equal(t, "error: domain name is required", err.Error())
}

func Test_Cmd_JSON(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	logFile := filepath.Join(t.TempDir(), "zns.json")
	t.Setenv("ZNS_LOG_FILE", logFile)

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--json", "--server", fmt.Sprintf("127.0.0.1:%d", DNSServerPort)})

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
	rootCmd.SetArgs([]string{"example.com", "--server", fmt.Sprintf("127.0.0.1:%d", DNSServerPort), "--query-type", "A"})

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
	rootCmd.SetArgs(append(args, "--server", fmt.Sprintf("127.0.0.1:%d", DNSServerPort)))
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

func Test_Cmd_MultipleDomains_error(t *testing.T) {
	t.Setenv("NO_COLOR", "1")

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "example.org", "--server", fmt.Sprintf("127.0.0.1:%d", DNSServerPort)})

	err := rootCmd.Execute()

	assert.Error(t, err)
	assert.Equal(t, "error: multiple domain names provided: example.com, example.org", err.Error())
}

func Test_Cmd_InvalidQueryType(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--server", fmt.Sprintf("127.0.0.1:%d", DNSServerPort), "--query-type", "BOGUS"})

	err := rootCmd.Execute()

	assert.Error(t, err)
	assert.Equal(t, "error: invalid query type: BOGUS", err.Error())
}

func Test_Cmd_Debug(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--debug", "--server", fmt.Sprintf("127.0.0.1:%d", DNSServerPort), "--query-type", "A"})

	err := rootCmd.Execute()

	assert.NoError(t, err)
}

func Test_Cmd_LogFile(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	file, err := os.CreateTemp(t.TempDir(), "zns")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	t.Setenv("ZNS_LOG_FILE", file.Name())

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--server", fmt.Sprintf("127.0.0.1:%d", DNSServerPort)})

	err = rootCmd.Execute()
	assert.NoError(t, err)

	assert.FileExists(t, file.Name())

	logFile, err := os.ReadFile(file.Name())
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

	file, err := os.CreateTemp(t.TempDir(), "zns")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	t.Setenv("ZNS_LOG_FILE", file.Name())

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--debug", "--server", fmt.Sprintf("127.0.0.1:%d", DNSServerPort)})

	err = rootCmd.Execute()
	assert.NoError(t, err)

	assert.FileExists(t, file.Name())

	logFile, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}

	assert.Contains(t, string(logFile), "Querying DNS server: server=127.0.0.1:53535 domain=example.com qtype=A")
	assert.Contains(t, string(logFile), "Querying DNS server: server=127.0.0.1:53535 domain=example.com qtype=CNAME")
	assert.Contains(t, string(logFile), "Received DNS response: server=127.0.0.1:53535 domain=example.com qtype=A rcode=NOERROR")
	assert.Contains(t, string(logFile), "Received DNS response: server=127.0.0.1:53535 domain=example.com qtype=CNAME rcode=NOERROR")
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
