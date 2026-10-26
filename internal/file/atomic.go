package file

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// WriteAtomic replaces a file only after its replacement has been fully written.
func WriteAtomic(path string, write func(io.Writer) error) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".wpprobe-db-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if existing, err := os.Stat(path); err == nil {
		if err := tmp.Chmod(existing.Mode().Perm()); err != nil {
			_ = tmp.Close()
			return err
		}
	} else if !os.IsNotExist(err) {
		_ = tmp.Close()
		return err
	}
	if err := write(tmp); err != nil {
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
	if runtime.GOOS != "windows" {
		return os.Rename(tmpPath, path)
	}

	// Windows cannot rename over an existing destination. Keep it available for
	// rollback until the replacement has reached its final path.
	backup, err := os.CreateTemp(filepath.Dir(path), ".wpprobe-db-backup-*")
	if err != nil {
		return err
	}
	backupPath := backup.Name()
	_ = backup.Close()
	if err := os.Remove(backupPath); err != nil {
		return err
	}
	if err := os.Rename(path, backupPath); err != nil {
		if os.IsNotExist(err) {
			return os.Rename(tmpPath, path)
		}
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if restoreErr := os.Rename(backupPath, path); restoreErr != nil {
			return fmt.Errorf("replace database: %w; restore previous database: %v", err, restoreErr)
		}
		return err
	}
	_ = os.Remove(backupPath)
	return nil
}
