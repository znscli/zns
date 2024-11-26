package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"
	"github.com/znscli/zns/internal/arguments"
	"github.com/znscli/zns/internal/query"
	"github.com/znscli/zns/internal/view"
)

var (
	version string

	debug   bool
	json    bool
	noColor bool

	server string
	qtype  string

	rootCmd = &cobra.Command{
		Use:     "zns",
		Short:   "zns - foobar",
		Version: version,
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) != 1 {
				fmt.Println("error: provide a domain name")
				fmt.Println("See 'zns -h' for help and examples")
				os.Exit(1)
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

			var w io.Writer = os.Stdout
			logFile := os.Getenv("ZNS_LOG_FILE")
			if logFile != "" {
				f, err := os.Create(logFile)
				if err != nil {
					panic(fmt.Sprintf("Failed to create log file: %v", err))
				}
				defer f.Close()
				w = f
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
			})

			// Log the debug state and current log level
			logger.Debug("Debug logging enabled", "debug", debug)
			logger.Debug("Log level", "level", logger.GetLevel())

			// Log the arguments and flags
			logger.Debug("Args", "args", args)
			logger.Debug("Flags", "server", server, "qtype", qtype, "debug", debug)

			// Create a new querier
			querier := query.NewQuerier(fmt.Sprintf("%s:53", server), logger)

			logger.Debug("Creating querier", "server", server, "qtype", qtype, "domain", args[0])

			// Prepare query types
			qtypes := make([]uint16, 0, len(query.QueryTypes))
			for _, qtype := range query.QueryTypes {
				qtypes = append(qtypes, qtype)
			}

			// Set specific query type if provided
			if qtype != "" {
				qtypeInt, ok := query.QueryTypes[strings.ToUpper(qtype)]
				if !ok {
					fmt.Printf("error: invalid query type: %s\n", qtype)
					os.Exit(1)
				}
				qtypes = []uint16{qtypeInt}
			}

			// Execute the queries
			messages, err := querier.MultiQuery(args[0], qtypes)
			if err != nil {
				if merr, ok := err.(*multierror.Error); ok {
					for _, e := range merr.Errors {
						fmt.Println(e)
					}
				} else {
					fmt.Println(err)
				}
				os.Exit(1)
			}

			sort.SliceStable(messages, func(i, j int) bool {
				return messages[i].Question[0].Qtype < messages[j].Question[0].Qtype
			})

			for _, m := range messages {
				for _, record := range m.Answer {
					v.Render(args[0], record)
				}
			}
		},
	}
)

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Flags().StringVarP(&server, "server", "s", "1.1.1.1", "DNS server to query")
	rootCmd.Flags().StringVarP(&qtype, "query-type", "q", "", "DNS query type")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "If set, debug output is printed")
	rootCmd.Flags().BoolVar(&json, "json", false, "If set, output is printed in JSON format.")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
