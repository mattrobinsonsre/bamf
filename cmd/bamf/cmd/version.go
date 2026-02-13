package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		if jsonOutput {
			info := map[string]string{
				"version":    Version,
				"git_commit": GitCommit,
				"build_time": BuildTime,
			}
			data, _ := json.MarshalIndent(info, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("bamf version %s\n", Version)
			fmt.Printf("  git commit: %s\n", GitCommit)
			fmt.Printf("  build time: %s\n", BuildTime)
		}
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
