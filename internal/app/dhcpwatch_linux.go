package app

import (
	"context"
	"net"
	"syscall"
)

// listenDHCPClient opens UDP :68 bound to one interface, able to broadcast.
// Needs CAP_NET_BIND_SERVICE (port 68) and CAP_NET_RAW (SO_BINDTODEVICE);
// the systemd unit from install.sh grants both.
func listenDHCPClient(ifname string) (net.PacketConn, error) {
	lc := net.ListenConfig{Control: func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); serr != nil {
				return
			}
			if serr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1); serr != nil {
				return
			}
			serr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifname)
		})
		if err != nil {
			return err
		}
		return serr
	}}
	return lc.ListenPacket(context.Background(), "udp4", ":68")
}
