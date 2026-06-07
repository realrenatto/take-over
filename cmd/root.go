package cmd

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"take-over/runner"
	"time"

	"github.com/spf13/cobra"
)

var opts = runner.Config{}

var rootCmd = &cobra.Command{
	Use:   "take-over",
	Short: "Take-Over is a Go-based tool designed to detect subdomain takeover vulnerabilities across different Cloud Service Providers (CSPs).",
	CompletionOptions: cobra.CompletionOptions{
		DisableDefaultCmd: true,
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		if opts.URL == "" && opts.List == "" {
			return fmt.Errorf("must provide --url (-u) or --list (-l)")
		}

		fingerprintsPath, err := runner.GetFingerprintPath()
		if err != nil {
			return err
		}
		if _, err := os.Stat(fingerprintsPath); errors.Is(err, fs.ErrNotExist) {
			fmt.Printf("[INF] Fingerprints not found; downloading to %q\n", fingerprintsPath)
			if err := runner.DownloadFingerprints(); err != nil {
				return err
			}
		} else {
			found, err := runner.CheckIntegrity()
			if err != nil {
				return err
			}
			if !found {
				fmt.Printf("[INF] Integrity mismatch; downloading updated fingerprints\n")
				if err := runner.DownloadFingerprints(); err != nil {
					return err
				}
			}
		}

		start := time.Now()
		if err := runner.Process(&opts); err != nil {
			return err
		}
		elapsed := time.Since(start)
		fmt.Printf("[INF] Scan completed in %s.\n", elapsed)
		return nil
	},
}

func Execute() {
	rootCmd.Execute()
}

const customHelp = `Take-Over is a Go-based tool designed to detect subdomain takeover vulnerabilities across different Cloud Service Providers (CSPs).

Usage:
   take-over [flags]

Flags:
   -u, --url string          target URL/host to scan
   -l, --list string         path to file containing a list of target URLs/hosts to scan (one per line)
   -c, --concurrency int     maximum number of targets to be executed in parallel (default 10)
   -o, --output string       output file to write found vulnerabilities
   -v, --verbose             show both vulnerable and non-vulnerable subdomains
   -h, --help                show help
`

func init() {
	rootCmd.Flags().StringVarP(&opts.URL, "url", "u", "", "target URL/host to scan")
	rootCmd.Flags().StringVarP(&opts.List, "list", "l", "", "path to file containing a list of target URLs/hosts to scan (one per line)")
	rootCmd.Flags().IntVarP(&opts.Concurrency, "concurrency", "c", 10, "maximum number of targets to be executed in parallel")
	rootCmd.Flags().StringVarP(&opts.Output, "output", "o", "", "output file to write found vulnerabilities")
	rootCmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false, "show both vulnerable and non-vulnerable subdomains")

	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		fmt.Print(customHelp)
	})
}
