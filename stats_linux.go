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
		case <-s.close:
			return
		case <-ticker.C:
			log.Debugf("TCP Conns: %v    UDP Conns: %v", s.NumTCPConns(), s.NumUDPConns())
			log.Debugf("Invalid Packets: %d    Accepted Packets: %d    Dropped Packets: %d", s.InvalidPackets(), s.AcceptedPackets(), s.DroppedPackets())
		}
	}
}

func (s *server) acceptedPacket() {
	atomic.AddInt64(&s.acceptedPackets, 1)
}

func (s *server) AcceptedPackets() int {
	return int(atomic.LoadInt64(&s.acceptedPackets))
}

func (s *server) invalidPacket() {
	atomic.AddInt64(&s.invalidPackets, 1)
}

func (s *server) InvalidPackets() int {
	return int(atomic.LoadInt64(&s.invalidPackets))
}

func (s *server) droppedPacket() {
	atomic.AddInt64(&s.droppedPackets, 1)
}

func (s *server) DroppedPackets() int {
	return int(atomic.LoadInt64(&s.droppedPackets))
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
