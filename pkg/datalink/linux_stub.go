//go:build !linux

package datalink

import "errors"

// OpenLinux is only implemented on Linux; AF_PACKET is a Linux facility.
func OpenLinux(string) (Transport, error) {
	return nil, errors.New("datalink: AF_PACKET transport is only supported on Linux")
}
