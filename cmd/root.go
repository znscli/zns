package cmd

import (
	"fmt"
	"os"

	"github.com/hashicorp/go-multierror"
	"github.com/spf13/cobra"
	"github.com/znscli/zns/internal/query"
)

var (
	version string

	debug bool

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

			// Initialize a new querier with the specified DNS server
			querier := query.NewQuerier("1.1.1.1:53", nil)

			qtypes := make([]uint16, 0, len(query.QueryTypes))
			for _, qtype := range query.QueryTypes {
				qtypes = append(qtypes, qtype)
			}

			messages, err := querier.QueryTypes(args[0], qtypes)
			if err != nil {
				if merr, ok := err.(*multierror.Error); ok {
					for _, e := range merr.Errors {
						fmt.Println(e)
					}
				} else { // This should never happen since all errors in zns are multierrors, but we handle it anyway.
					fmt.Println(err)
				}
				os.Exit(1)
			}

			for _, msg := range messages {
				fmt.Println(msg)
			}
		},
	}
)

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.Flags().BoolVarP(&debug, "debug", "d", false, "verbose logging")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
