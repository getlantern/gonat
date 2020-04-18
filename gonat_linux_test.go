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
		s, err := NewServer(&ReadWriterAdapter{dev}, &Opts{
			IdleTimeout:   2 * time.Second,
			StatsInterval: 250 * time.Millisecond,
			BufferDepth:   1,
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
			s.Serve()
			_s := s.(*server)
			assert.True(t, _s.bufferPool.NumPooled() > 0, "buffers should be returned to pool")
			_s.opts.StatsTracker.Close()
			close(finishedCh)
		}()
		return func() error { return nil }, nil
	})
}
