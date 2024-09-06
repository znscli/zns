package cmd

import (
	"fmt"
	"os"

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

