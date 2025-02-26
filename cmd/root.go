package cmd

import (
	"fmt"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
	"github.com/znscli/zns/internal/arguments"
	"github.com/znscli/zns/internal/query"
	"github.com/znscli/zns/internal/view"
)

const (
	resolveConfPath = "/etc/resolv.conf"
)

var (
	version = "dev"
	debug   bool
	json    bool
	noColor bool
	server  string
	qtype   string
)

// EnsureDNSAddress formats the DNS server address properly.
func EnsureDNSAddress(server string) string {
    if strings.Contains(server, "]") || strings.Contains(server, ":") && net.ParseIP(server) == nil {
        return server
    }

    ip := net.ParseIP(server)
    if ip != nil && ip.To4() == nil { // It's IPv6 (and not IPv4)
        return "[" + server + "]:53"
    }
    // Otherwise, assume IPv4 or hostname, so append port normally.
    return server + ":53"
}

func NewRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "zns",
		Short: "zns is a command-line utility for querying DNS records and displaying them in human- or machine-readable formats.",
		Long:  "zns is a command-line utility for querying DNS records, displaying them in a human-readable, colored format that includes type, name, TTL, and value. It supports various DNS record types, concurrent queries for improved performance, JSON output format for machine-readable results, and options to write output to a file or query a specific DNS server.",
		Example: `
  # Query DNS records for example.com
  zns example.com

  # Query a specific record type
  zns example.com -q NS

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
			if len(args) != 1 {
				return fmt.Errorf("error: domain name is required")
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

			var vt arguments.ViewType
			if json {
				vt = arguments.ViewJSON
			} else {
				vt = arguments.ViewHuman
			}

			var w = view.NewTabWriter(os.Stdout, debug)
			logFile := os.Getenv("ZNS_LOG_FILE")
			if logFile != "" {
				f, err := os.Create(logFile)
				if err != nil {
					return fmt.Errorf("error: failed to create log file: %v", err)
				}
				defer f.Close()
				w = view.NewTabWriter(f, debug)
			}

			v := view.NewRenderer(vt, &view.View{
				Stream: &view.Stream{
					Writer: w,
				},
			})

			logger := hclog.New(&hclog.LoggerOptions{
				Name:                 "zns",
				Output:               w,
				Level:                hclog.LevelFromString(logLevel),
				Color:                color,
				ColorHeaderAndFields: !noColor,
				DisableTime:          false,
				JSONFormat:           json,
			}).With("@domain", args[0])

			logger.Debug("Debug logging enabled", "debug", debug)
			logger.Debug("Log level", "level", logger.GetLevel())

			logger.Debug("Args", "args", args)
			logger.Debug("Flags", "server", server, "qtype", qtype, "debug", debug)

			// Resolve the DNS nameserver from the host.
			// Supported only on Unix-like systems.
			// On Windows, dynamic DNS resolution is not supported;
			// a DNS nameserver must be explicitly specified using the --server flag.
			if server == "" {
				switch runtime.GOOS {
				case "windows":
					return fmt.Errorf("error: host DNS nameserver resolution is not supported on Windows; please specify a DNS server using the --server flag")
				default:
					logger.Debug(fmt.Sprintf("Resolving DNS nameserver from \"%s\"", resolveConfPath), "path", resolveConfPath)

					// Attempt to retrieve the DNS nameserver from `/etc/resolv.conf`.
					conf, err := dns.ClientConfigFromFile(resolveConfPath)
					if err != nil {
						return fmt.Errorf("error: failed to read %s: %v", resolveConfPath, err)
					}

					if len(conf.Servers) == 0 {
						return fmt.Errorf("error: no DNS nameservers found in %s", resolveConfPath)
					}

					server = conf.Servers[0] // Use the first available DNS nameserver.
					logger.Debug(fmt.Sprintf("Using DNS nameserver %s", server), "server", server, "path", resolveConfPath)
				}
			}

			server = EnsureDNSAddress(server)

			querier := query.NewQueryClient(server, new(dns.Client), logger)

			logger.Debug("Creating querier", "server", server, "qtype", qtype, "domain", args[0])

			// Create a slice of supported query types to query.
			qtypes := make([]uint16, 0, len(query.QueryTypes))
			for _, qtype := range query.QueryTypes {
				qtypes = append(qtypes, qtype)
			}

			// Filter down to the specified query type, if provided.
			if qtype != "" {
				qtypeInt, ok := query.QueryTypes[strings.ToUpper(qtype)]
				if !ok {
					return fmt.Errorf("error: invalid query type: %s", qtype)
				}
				qtypes = []uint16{qtypeInt}
			}

			messages, err := querier.MultiQuery(args[0], qtypes)
			if err != nil {
				if merr, ok := err.(*multierror.Error); ok {
					return merr
				} else {
					return err
				}
			}

			// Sort the messages by query type, so the output is consistent.
			sort.SliceStable(messages, func(i, j int) bool {
				return messages[i].Question[0].Qtype < messages[j].Question[0].Qtype
			})

			for _, m := range messages {
				for _, record := range m.Answer {
					v.Render(args[0], record)
				}
			}
			w.Flush() // we need to flush the buffer to ensure all data is written to the underlying stream.

			return nil
		},
	}

	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.Flags().StringVarP(&server, "server", "s", "", "DNS server to query")
	cmd.Flags().StringVarP(&qtype, "query-type", "q", "", "DNS query type")
	cmd.Flags().BoolVar(&debug, "debug", false, "Enable debug output")
	cmd.Flags().BoolVar(&json, "json", false, "Output in JSON format")

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
