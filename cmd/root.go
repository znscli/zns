package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"
	"github.com/znscli/zns/internal/query"
)

var (
	version string

	debug  bool
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

			// Determine log level based on environment variable and debug flag
			logLevel := os.Getenv("ZNS_LOG_LEVEL")
			if debug {
				logLevel = "DEBUG" // Override log level to DEBUG if the debug flag is set
			}

			logger := hclog.New(&hclog.LoggerOptions{
				Name:                 "zns",
				Level:                hclog.LevelFromString(logLevel),
				Color:                hclog.AutoColor,
				ColorHeaderAndFields: true,
				DisableTime:          true,
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

			// Execute the query
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

			// Print the records
			printRecords(args[0], messages)
		},
	}
)

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Flags().StringVarP(&server, "server", "s", "1.1.1.1", "DNS server to query")
	rootCmd.Flags().StringVarP(&qtype, "query-type", "q", "", "DNS query type")
	rootCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
