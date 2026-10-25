//go:build windows

package supervise

import (
	"context"
	"errors"
	"io"
	"time"
)

type Process struct{ Name, After, Command string }

func Parse(io.Reader) ([]Process, error) {
	return nil, errors.New("supervise runs only in the Linux server container")
}
func Run(context.Context, []Process, time.Duration) error {
	return errors.New("supervise runs only in the Linux server container")
}
