//go:build windows

package fileserver

import "os"

// The per-user temp directory is already private on Windows.
func private(os.FileInfo) bool { return true }
