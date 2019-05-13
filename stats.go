package gonat

import (
	"sync/atomic"
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
			log.Debugf("TCP Conns: %v    UDP Ports: %v", s.NumTCPConns(), s.NumUDPPorts())
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

func (s *server) addTCPConn() {
	atomic.AddInt64(&s.numTcpConns, 1)
}

func (s *server) removeTCPConn() {
	atomic.AddInt64(&s.numTcpConns, -1)
}

func (s *server) NumTCPConns() int {
	return int(atomic.LoadInt64(&s.numTcpConns))
}

func (s *server) addUDPPort() {
	atomic.AddInt64(&s.numUdpPorts, 1)
}

func (s *server) removeUDPPort() {
	atomic.AddInt64(&s.numUdpPorts, -1)
}

func (s *server) NumUDPPorts() int {
	return int(atomic.LoadInt64(&s.numUdpPorts))
}
