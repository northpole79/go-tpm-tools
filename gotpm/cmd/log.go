package cmd

import (
	"encoding/hex"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/spf13/cobra"
)

// logCmd represents the log command
var logCmd = &cobra.Command{
	Use:   "log",
	Short: "Parse the TCG Event Log",
	Long: `These commands help parse the TCG event log.

When the PCRs of a TPM are extended, TODO`,
}

var parseCmd = &cobra.Command{
	Use:   "events",
	Short: "Extract events from an Event Log",
	Long:  `TODO`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		tcgLog, err := tpm2tools.ParseLog(getLog())
		if err != nil {
			return err
		}
		fmt.Fprintf(messageOutput(), "Parsed %d events from event log\n", len(tcgLog))

		for _, event := range tcgLog {
			fmt.Fprintf(dataOutput(), "PCR %d: %s\n", event.PcrIndex, event.PcrEventName)
			fmt.Fprintf(dataOutput(), "\tData: %s\n", event.PcrEventData)
			for _, digest := range event.Digests {
				fmt.Fprintf(dataOutput(), "\tDigest(%v): %s\n", digest.DigestAlg, hex.EncodeToString(digest.Digest))
			}
		}
		return nil
	},
}

var expectedCmd = &cobra.Command{
	Use:   "pcrs",
	Short: "Compute PCRs for an Event Log",
	Long:  `TODO`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return nil
	},
}

var (
	useCurrent bool
)

func init() {
	RootCmd.AddCommand(logCmd)
	logCmd.AddCommand(parseCmd)
	logCmd.AddCommand(expectedCmd)

	addInputFlag(logCmd)
	addOutputFlag(logCmd)
	logCmd.PersistentFlags().BoolVar(&useCurrent, "use-current", true,
		"Use the system log from the current boot")
}

func getLog() io.Reader {
	if !useCurrent {
		return dataInput()
	}

	r, err := getSystemLog()
	if err != nil {
		return alwaysError{fmt.Errorf("getting system log: %v", err)}
	}
	return r
}
