//go:build !linux

package service

import "errors"

const Unit = "porthub-private"

var errUnsupported = errors.New("system service install is not supported on this OS yet")

func Install(string) error            { return errUnsupported }
func Uninstall(bool) error            { return errUnsupported }
func Status() (string, string, error) { return "", "", errUnsupported }
