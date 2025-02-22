package cmd

import (
	"fmt"
	"log"
	"net"
	"os"
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

	w.WriteMsg(&msg)
}

func Test_Cmd(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--server", fmt.Sprintf("127.0.0.01:%d", DNSServerPort)})

	err := rootCmd.Execute()

	assert.NoError(t, err)
}

func Test_Cmd_Error(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"--server", fmt.Sprintf("127.0.0.01:%d", DNSServerPort)})

	err := rootCmd.Execute()

	assert.Error(t, err)
	assert.Equal(t, "error: domain name is required", err.Error())
}

func Test_Cmd_JSON(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--json", "--server", fmt.Sprintf("127.0.0.01:%d", DNSServerPort)})

	err := rootCmd.Execute()

	assert.NoError(t, err)
}

func Test_Cmd_QueryType(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--server", fmt.Sprintf("127.0.0.01:%d", DNSServerPort), "--query-type", "A"})

	err := rootCmd.Execute()

	assert.NoError(t, err)
}

func Test_Cmd_Debug(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--debug", "--server", fmt.Sprintf("127.0.0.01:%d", DNSServerPort), "--query-type", "A"})

	err := rootCmd.Execute()

	assert.NoError(t, err)
}

func Test_Cmd_LogFile(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	file, err := os.CreateTemp("", "zns")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	t.Setenv("ZNS_LOG_FILE", file.Name())

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--server", fmt.Sprintf("127.0.0.01:%d", DNSServerPort)})

	err = rootCmd.Execute()
	assert.NoError(t, err)

	assert.FileExists(t, file.Name())

	logFile, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}

	assert.Contains(t, string(logFile), "A       example.com.   01m00s   93.184.216.34")
	assert.Contains(t, string(logFile), "CNAME   example.com.   01m00s   example.org")
}

func Test_Cmd_LogFile_Debug(t *testing.T) {
	t.Setenv("NO_COLOR", "1") // Disable color codes for easier testing

	file, err := os.CreateTemp("", "zns")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(file.Name())

	t.Setenv("ZNS_LOG_FILE", file.Name())

	rootCmd := NewRootCommand()
	rootCmd.SetArgs([]string{"example.com", "--debug", "--server", fmt.Sprintf("127.0.0.01:%d", DNSServerPort)})

	err = rootCmd.Execute()
	assert.NoError(t, err)

	assert.FileExists(t, file.Name())

	logFile, err := os.ReadFile(file.Name())
	if err != nil {
		t.Fatal(err)
	}

	assert.Contains(t, string(logFile), "Querying DNS server: @domain=example.com server=127.0.0.01:53535 domain=example.com qtype=A")
	assert.Contains(t, string(logFile), "Querying DNS server: @domain=example.com server=127.0.0.01:53535 domain=example.com qtype=CNAME")
	assert.Contains(t, string(logFile), "Received DNS response: @domain=example.com server=127.0.0.01:53535 domain=example.com qtype=A rcode=NOERROR")
	assert.Contains(t, string(logFile), "Received DNS response: @domain=example.com server=127.0.0.01:53535 domain=example.com qtype=CNAME rcode=NOERROR")
	assert.Contains(t, string(logFile), "A       |example.com.   |01m00s   |93.184.216.34")
	assert.Contains(t, string(logFile), "CNAME   |example.com.   |01m00s   |example.org")
}
