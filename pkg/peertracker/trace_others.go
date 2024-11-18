//go:build !linux
// +build !linux

package peertracker

import (
	"errors"
	"net"
)

func CallerFromVSockConn(conn net.Conn) (CallerInfo, error) {
	return CallerInfo{}, errors.New("not supported")
}
