package file

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAtomicKeepsOldFileOnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "database.json")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("transfer interrupted")
	err := WriteAtomic(path, func(w io.Writer) error {
		_, _ = io.WriteString(w, "partial")
		return wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("WriteAtomic error = %v, want %v", err, wantErr)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "old" {
		t.Fatalf("database = %q, error = %v, want old", got, err)
	}
}

func TestNewJSONWriterReportsOpenError(t *testing.T) {
	w := NewJSONWriter(t.TempDir())
	if w.Err() == nil {
		t.Fatal("expected an error for an output path that is a directory")
	}
	w.Close()
}
