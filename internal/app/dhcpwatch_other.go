//go:build !linux

package app

import (
	"errors"
	"net"
)

func listenDHCPClient(string) (net.PacketConn, error) {
	return nil, errors.New("dò DHCP giả mạo chỉ hỗ trợ khi DrayPulse chạy trên Linux")
}
