// +build linux

package gonat

import (
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

const (
	tunGW = "10.0.0.9"
)

// Note - this test has to be run with root permissions to allow setting up the
// TUN device.
func TestEndToEnd(t *testing.T) {
	RunTest(t, "tun0", "10.0.0.10", tunGW, "255.255.255.0", 1500, func(ifAddr string, dev io.ReadWriter, origEchoAddr Addr, finishedCh chan interface{}) (func() error, error) {
		server, err := NewServer(dev, &Opts{
			StatsInterval: 250 * time.Millisecond,
			OnOutbound: func(pkt *IPPacket) {
				pkt.SetDest(origEchoAddr)
			},
			OnInbound: func(pkt *IPPacket, downFT FiveTuple) {
				pkt.SetSource(Addr{tunGW, downFT.Dst.Port})
			},
		})
		if err != nil {
			return nil, err
		}

		go func() {
			assert.Equal(t, io.EOF, server.Serve())
			close(finishedCh)
		}()
		return func() error { return nil }, nil
	})
}
