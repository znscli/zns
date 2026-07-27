package cmd

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/znscli/zns/internal/dnssec"
	"github.com/znscli/zns/internal/query"
	"github.com/znscli/zns/internal/view"
)

var (
	version        = "dev"
	debug          bool
	jsonOutput     bool
	noColor        bool
	server         string
	queryTypes     []string
	dnssecRecords  bool
	dnssecValidate bool
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

// renderValidated groups an answer section into RRsets, validates each
// against the DNSSEC chain of trust, and renders every record with the
// status of its RRset. RRSIG records take the status of the RRset they
// cover.
func renderValidated(renderer view.Renderer, validator *dnssec.Validator, domain string, answers []dns.RR) {
	type setKey struct {
		name  string
		qtype uint16
	}
	key := func(rr dns.RR) setKey {
		if sig, ok := rr.(*dns.RRSIG); ok {
			return setKey{strings.ToLower(sig.Hdr.Name), sig.TypeCovered}
		}
		return setKey{strings.ToLower(rr.Header().Name), rr.Header().Rrtype}
	}

	rrsets := make(map[setKey][]dns.RR)
	sigs := make(map[setKey][]*dns.RRSIG)
	for _, rr := range answers {
		k := key(rr)
		if sig, ok := rr.(*dns.RRSIG); ok {
			sigs[k] = append(sigs[k], sig)
			continue
		}
		rrsets[k] = append(rrsets[k], rr)
	}

	statuses := make(map[setKey]dnssec.Status, len(rrsets))
	for k, rrset := range rrsets {
		status, _ := validator.Validate(rrset, sigs[k])
		statuses[k] = status
	}

	for _, rr := range answers {
		k := key(rr)
		status, ok := statuses[k]
		if !ok {
			// An RRSIG whose covered RRset is absent, e.g. from an explicit
			// RRSIG query: there is nothing to validate it against, but every
			// row still carries a status while validating.
			status = dnssec.StatusUnknown
		}
		renderer.RenderDNSSEC(domain, rr, status)
	}
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

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zns <domain> [record types...]",
		Short: "A fast and friendly DNS lookup tool",
		Long: `zns queries DNS records and presents them in a clean, colored table or as JSON.

By default all common record types are queried concurrently. Specific types
can be requested as arguments or with --query-type, and DNSSEC records can be
included and validated against the chain of trust.`,
		Example: `  # Look up example.com
  zns example.com

  # Specific record types
  zns example.com -q NS
  zns example.com A AAAA MX

  # DNSSEC: include RRSIGs, or validate the chain of trust
  zns example.com --dnssec
  zns example.com --dnssec-validate

  # Query a specific DNS server
  zns example.com --server 1.1.1.1

  # Machine-readable output
  zns example.com --json | jq`,
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
				logger.Debug("Resolved DNS nameserver from host", "server", server)
			}
			server = EnsureDNSAddress(server)

			querier := query.NewQueryClient(server, new(dns.Client), logger)
			// Retry truncated UDP responses over TCP, where the full answer fits.
			querier.Fallback = &dns.Client{Net: "tcp"}
			querier.DNSSEC = dnssecRecords || dnssecValidate
			querier.Validate = dnssecValidate
			messages, err := querier.MultiQuery(domain, qtypes)
			if err != nil {
				return err
			}

			var validator *dnssec.Validator
			if dnssecValidate {
				validator = dnssec.NewValidator(querier, dnssec.RootAnchors())
			}
			for _, m := range messages {
				// Surface failures such as resolver-side DNSSEC validation
				// errors instead of silently rendering nothing.
				if m.Rcode != dns.RcodeSuccess && m.Rcode != dns.RcodeNameError {
					fmt.Fprintf(os.Stderr, "warning: %s query for %s returned %s\n",
						dns.Type(m.Question[0].Qtype).String(), domain, dns.RcodeToString[m.Rcode])
				}
				// A truncated answer may hold a partial RRset, whose signature
				// then fails to verify for reasons that are not tampering.
				if m.Truncated {
					fmt.Fprintf(os.Stderr, "warning: %s answer for %s is truncated and may be incomplete\n",
						dns.Type(m.Question[0].Qtype).String(), domain)
				}
				if validator != nil {
					renderValidated(renderer, validator, domain, m.Answer)
					continue
				}
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
	cmd.Flags().StringSliceVarP(&queryTypes, "query-type", "q", nil, "record types to query, comma-separated or repeated (e.g. -q A,AAAA)")
	cmd.Flags().BoolVar(&debug, "debug", false, "Enable debug output")
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output in JSON format")
	cmd.Flags().BoolVar(&dnssecRecords, "dnssec", false, "Request DNSSEC records (sets the DO bit, returning RRSIGs)")
	cmd.Flags().BoolVar(&dnssecValidate, "dnssec-validate", false, "Validate records against the DNSSEC chain of trust (implies --dnssec)")

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
