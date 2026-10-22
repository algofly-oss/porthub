package tunnel

import (
	"bytes"
	"context"
	"os"
	"time"
)

// RunFile runs the client for a rathole-format TOML file and re-applies it
// when the file changes; an invalid edit keeps the last valid configuration.
func RunFile(ctx context.Context, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	config, err := ParseConfig(data)
	if err != nil {
		return err
	}
	client := New(nil)
	defer client.Close()
	client.Apply(ctx, config)
	client.logger.Printf("running %d service(s) via %s", len(config.Services), config.RemoteAddr)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		next, err := os.ReadFile(path)
		if err != nil || bytes.Equal(next, data) {
			continue
		}
		data = next
		updated, err := ParseConfig(next)
		if err != nil {
			client.logger.Printf("ignoring invalid configuration change: %v", err)
			continue
		}
		client.Apply(ctx, updated)
		client.logger.Printf("configuration reloaded: %d service(s)", len(updated.Services))
	}
}
