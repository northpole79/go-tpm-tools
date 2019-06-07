package cmd

import (
	"bytes"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil/tbs"
)

// There is no need for flags on Windows, as there is no concept of a TPM path.
func openImpl() (io.ReadWriteCloser, error) {
	return tpm2.OpenTPM()
}

// On Windows, we get the event log from the TBS
func getSystemLog() (io.Reader, error) {
	tpmContext, err := tbs.CreateContext(tbs.TPMVersion20, tbs.IncludeTPM12|tbs.IncludeTPM20)
	if err != nil {
		return nil, err
	}

	var buf []byte
	for {
		size, err := tpmContext.GetTCGLog(buf)
		if err != nil && err != tbs.ErrInsufficientBuffer {
			return nil, err
		}
		if uint(size) <= uint(len(buf)) && err == nil {
			return bytes.NewBuffer(buf[:size]), nil
		}

		buf = make([]byte, size)
	}
}
