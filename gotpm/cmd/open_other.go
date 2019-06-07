// +build !windows

package cmd

import (
	"io"
	"os"

	"github.com/google/go-tpm/tpm2"
)

var tpmPath string

func init() {
	RootCmd.PersistentFlags().StringVar(&tpmPath, "tpm-path", "/dev/tpm0",
		"path to TPM device")
}

// On Linux, we have to pass in the TPM path though a flag
func openImpl() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM(tpmPath)
}

// On Linux, we get the event log from sysfs
func getSystemLog() (io.Reader, error) {
	return os.Open("/sys/kernel/security/tpm0/binary_bios_measurements")
}
