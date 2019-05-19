package gonat

import (
	"sync/atomic"
	"syscall"
	"time"
)

func (s *server) trackStats() {
	ticker := time.NewTicker(s.opts.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		// case <-s.closeCh:
		// 	return
		case <-ticker.C:
			log.Debugf("TCP Conns: %v    UDP Conns: %v", s.NumTCPConns(), s.NumUDPConns())
			log.Debugf("Accepted Packets: %d    Rejected Packets: %d", s.AcceptedPackets(), s.RejectedPackets())
		}
	}
}

func (s *server) acceptedPacket() {
	atomic.AddInt64(&s.acceptedPackets, 1)
}

func (s *server) AcceptedPackets() int {
	return int(atomic.LoadInt64(&s.acceptedPackets))
}

func (s *server) rejectedPacket() {
	atomic.AddInt64(&s.rejectedPackets, 1)
}

func (s *server) RejectedPackets() int {
	return int(atomic.LoadInt64(&s.rejectedPackets))
}

func (s *server) addConn(proto uint8) {
	switch proto {
	case syscall.IPPROTO_TCP:
		atomic.AddInt64(&s.numTCPConns, 1)
	case syscall.IPPROTO_UDP:
		atomic.AddInt64(&s.numUDPConns, 1)
	}
}

func (s *server) removeConn(proto uint8) {
	switch proto {
	case syscall.IPPROTO_TCP:
		atomic.AddInt64(&s.numTCPConns, -1)
	case syscall.IPPROTO_UDP:
		atomic.AddInt64(&s.numUDPConns, -1)
	}
}

func (s *server) NumTCPConns() int {
	return int(atomic.LoadInt64(&s.numTCPConns))
}

func (s *server) NumUDPConns() int {
	return int(atomic.LoadInt64(&s.numUDPConns))
}
