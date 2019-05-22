// +build linux

package gonat

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	tunGW = "10.0.0.9"
)

// Note - this test has to be run with root permissions to allow setting up the
// TUN device.
func TestEndToEnd(t *testing.T) {
	RunTest(t, tunGW, func(dev io.ReadWriter, origEchoAddr Addr, finishedCh chan interface{}) func() error {
		server, err := NewServer(dev, &Opts{
			OnOutbound: func(pkt *IPPacket) {
				pkt.SetDest(origEchoAddr)
			},
			OnInbound: func(pkt *IPPacket, downFT FiveTuple) {
				pkt.SetSource(Addr{tunGW, downFT.Dst.Port})
			},
		})
		if !assert.NoError(t, err) {
			return nil
		}

		go func() {
			assert.Equal(t, io.EOF, server.Serve())
			close(finishedCh)
		}()
		return server.Close
	})
}
