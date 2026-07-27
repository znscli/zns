package cmd

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/znscli/zns/internal/query"
	"github.com/znscli/zns/internal/view"
)

const (
	resolveConfPath = "/etc/resolv.conf"
)

var (
	version    = "dev"
	debug      bool
	jsonOutput bool
	noColor    bool
	server     string
	queryTypes []string
)

// parseQueryArgs splits the positional arguments into the domain name and the
// requested query types: any argument matching a record type name (e.g. "A",
// "caa") counts as a type, the remaining argument is the domain. A domain
// that collides with a type name can be given with a trailing dot ("mx.").
// Flag-provided types come first, duplicates are dropped, and order is
// preserved so results render in the requested order.
func parseQueryArgs(flagTypes, args []string) (string, []uint16, error) {
	var domain string
	qtypes := make([]uint16, 0, len(flagTypes)+len(args))
	seen := make(map[uint16]bool)

	addType := func(qtype uint16) {
		if !seen[qtype] {
			seen[qtype] = true
			qtypes = append(qtypes, qtype)
		}
	}

	for _, name := range flagTypes {
		qtype, err := query.ParseQueryType(name)
		if err != nil {
			return "", nil, fmt.Errorf("error: %w", err)
		}
		addType(qtype)
	}
	for _, arg := range args {
		if qtype, err := query.ParseQueryType(arg); err == nil {
			addType(qtype)
			continue
		}
		if domain != "" {
			return "", nil, fmt.Errorf("error: multiple domain names provided: %s, %s", domain, arg)
		}
		domain = arg
	}

	if domain == "" {
		return "", nil, fmt.Errorf("error: domain name is required")
	}
	if len(qtypes) == 0 {
		qtypes = query.DefaultQueryTypes
	}
	return domain, qtypes, nil
}

// EnsureDNSAddress appends the default DNS port (53) to a server address that
// lacks one, bracketing IPv6 addresses as needed.
func EnsureDNSAddress(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server // Already host:port or [host]:port.
	}
	host := strings.TrimSuffix(strings.TrimPrefix(server, "["), "]")
	return net.JoinHostPort(host, "53")
}

// systemNameserver returns the first DNS nameserver configured on the host.
// Supported only on Unix-like systems. On Windows, dynamic DNS resolution is
// not supported; a DNS nameserver must be explicitly specified using the
// --server flag.
func systemNameserver() (string, error) {
	if runtime.GOOS == "windows" {
		return "", fmt.Errorf("error: host DNS nameserver resolution is not supported on Windows; please specify a DNS server using the --server flag")
	}

	conf, err := dns.ClientConfigFromFile(resolveConfPath)
	if err != nil {
		return "", fmt.Errorf("error: failed to read %s: %v", resolveConfPath, err)
	}
	if len(conf.Servers) == 0 {
		return "", fmt.Errorf("error: no DNS nameservers found in %s", resolveConfPath)
	}
	return conf.Servers[0], nil
}

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zns",
		Short: "zns is a command-line utility for querying DNS records and displaying them in human- or machine-readable formats.",
		Long:  "zns is a command-line utility for querying DNS records, displaying them in a human-readable, colored format that includes type, name, TTL, and value. It supports all common DNS record types, concurrent queries for improved performance, JSON output format for machine-readable results, and options to write output to a file or query a specific DNS server.",
		Example: `
  # Query DNS records for example.com
  zns example.com

  # Query a specific record type
  zns example.com -q NS

  # Query multiple record types
  zns example.com A CAA
  zns example.com -q A,CAA

  # Use a specific DNS server
  zns example.com -q NS --server 1.1.1.1

  # JSON output
  zns example.com --json | jq

  # Writing to a file
  export ZNS_LOG_FILE=/tmp/zns.log
  zns example.com
`,
		Version:       version,
		SilenceErrors: true, // We handle errors ourselves.
		SilenceUsage:  true, // Prevents the automatic rendering of the usage message when an error occurs.
		RunE: func(cmd *cobra.Command, args []string) error {
			domain, qtypes, err := parseQueryArgs(queryTypes, args)
			if err != nil {
				return err
			}

			var color hclog.ColorOption
			if os.Getenv("NO_COLOR") != "" {
				noColor = true
				color = hclog.ColorOff
			} else {
				color = hclog.AutoColor
			}

			logLevel := os.Getenv("ZNS_LOG_LEVEL")
			if debug {
				logLevel = "DEBUG"
			}

			out := io.Writer(os.Stdout)
			if logFile := os.Getenv("ZNS_LOG_FILE"); logFile != "" {
				f, err := os.Create(logFile)
				if err != nil {
					return fmt.Errorf("error: failed to create log file: %v", err)
				}
				defer f.Close()
				out = f
			}
			w := view.NewTabWriter(out, debug)

			vt := view.ViewHuman
			if jsonOutput {
				vt = view.ViewJSON
			}
			renderer := view.NewRenderer(vt, w)

			logOutput := io.Writer(w)
			if jsonOutput {
				// Keep the machine-readable stream free of diagnostics; hclog
				// uses its own @-prefixed JSON envelope.
				logOutput = os.Stderr
			}
			logger := hclog.New(&hclog.LoggerOptions{
				Name:                 "zns",
				Output:               logOutput,
				Level:                hclog.LevelFromString(logLevel),
				Color:                color,
				ColorHeaderAndFields: !noColor,
				JSONFormat:           jsonOutput,
			})
			logger.Debug("Flags", "server", server, "qtypes", strings.Join(queryTypes, ","), "debug", debug)

			if server == "" {
				resolved, err := systemNameserver()
				if err != nil {
					return err
				}
				server = resolved
				logger.Debug("Resolved DNS nameserver from host", "server", server, "path", resolveConfPath)
			}
			server = EnsureDNSAddress(server)

			querier := query.NewQueryClient(server, new(dns.Client), logger)
			// Retry truncated UDP responses over TCP, where the full answer fits.
			querier.Fallback = &dns.Client{Net: "tcp"}
			messages, err := querier.MultiQuery(domain, qtypes)
			if err != nil {
				return err
			}

			for _, m := range messages {
				for _, record := range m.Answer {
					renderer.Render(domain, record)
				}
			}
			// Flush the tabwriter to ensure all data is written to the underlying stream.
			_ = w.Flush()

			return nil
		},
	}

	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.Flags().StringVarP(&server, "server", "s", "", "DNS server to query")
	cmd.Flags().StringSliceVarP(&queryTypes, "query-type", "q", nil, "DNS query types, comma-separated or repeated (e.g. -q A,AAAA or -q CAA -q MX); bare record types may also be given as arguments")
	cmd.Flags().BoolVar(&debug, "debug", false, "Enable debug output")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")

	return cmd
}

func Execute() {
	rootCmd := NewRootCommand()
	if err := rootCmd.Execute(); err != nil {
		if merr, ok := err.(*multierror.Error); ok {
			for _, e := range merr.Errors {
				fmt.Fprintln(os.Stderr, e)
			}
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
	}
}
