package logrotate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RotateTree renames oversized *.log files under root (REQ-OBS-006).
// Pattern: app.log → app.log.1 → … → app.log.N (N=keep); oldest dropped.
// Does not signal nginx — caller must reopen after any rotation.
func RotateTree(root string, maxBytes int64, keep int) (rotated []string, err error) {
	if maxBytes < 1 {
		return nil, fmt.Errorf("maxBytes must be >= 1")
	}
	if keep < 1 {
		keep = 1
	}
	if keep > 30 {
		keep = 30
	}
	root = filepath.Clean(root)
	err = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		// active logs end with .log; rotated are .log.1 /.log.2 (suffix not .log)
		if !strings.HasSuffix(name, ".log") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() < maxBytes {
			return nil
		}
		if err := rotateOne(path, keep); err != nil {
			return err
		}
		rotated = append(rotated, path)
		return nil
	})
	return rotated, err
}

func rotateOne(path string, keep int) error {
	// delete oldest
	_ = os.Remove(fmt.Sprintf("%s.%d", path, keep))
	for i := keep - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", path, i)
		dst := fmt.Sprintf("%s.%d", path, i+1)
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
		}
	}
	if err := os.Rename(path, path+".1"); err != nil {
		return err
	}
	// recreate empty so processes that append without reopen still have a target briefly
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}
