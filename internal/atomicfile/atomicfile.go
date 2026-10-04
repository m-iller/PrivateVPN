package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
)

// Write replaces path with data. The file mode is 0600.
func Write(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replace(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func replace(tmp, path string) error {
	err := os.Rename(tmp, path)
	if err == nil {
		return nil
	}
	// Windows rename does not replace an existing file.
	if runtime.GOOS == "windows" {
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			return err
		}
		return os.Rename(tmp, path)
	}
	return err
}
