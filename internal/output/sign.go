package output

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/go-while/go-echolot/internal/fileutil"
)

// SignFunc returns the signature file (<name>.minisig, design §9.5) of
// the output file name with contents data, or nil if name isn't signed.
// It's called after the file is written, with exactly the bytes written.
type SignFunc func(name string, data []byte) ([]byte, error)

// SigSuffix is what a signature file adds to the name of its file.
const SigSuffix = ".minisig"

// writeSignature writes dir/name.minisig for data, after dir/name.  A
// file sign doesn't sign (or a nil sign) has its old signature removed:
// it would no longer match.  The file and its signature are two atomic
// writes, file first; a client that fetches between them sees a mismatch
// and keeps its last copy until its next fetch.
func writeSignature(dir, name string, data []byte, sign SignFunc) error {
	path := filepath.Join(dir, name+SigSuffix)
	var sig []byte
	if sign != nil {
		var err error
		if sig, err = sign(name, data); err != nil {
			return err
		}
	}
	if sig == nil {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	return fileutil.WriteAtomic(path, sig, filePerm)
}

// WritePingerKey writes dir/pinger.pub, the public key of the pinger's
// signatures, if it changed.
func WritePingerKey(dir string, file []byte) error {
	_, err := writeIfChanged(dir, "pinger.pub", file)
	return err
}
