package gonat

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/getlantern/errors"
	"github.com/getlantern/ops"
	ct "github.com/ti-mo/conntrack"
)

type server struct {
	acceptedPackets int64
	rejectedPackets int64
	numTCPConns     int64
	numUDPConns     int64

	tcpSocket          io.ReadWriteCloser
	udpSocket          io.ReadWriteCloser
	downstream         io.ReadWriter
	opts               *Opts
	bufferPool         BufferPool
	ctrack             *ct.Conn
	ctTimeout          uint32
	randomPortSequence []uint16
	portIndexes        map[uint8]map[Addr]int
	conns              map[uint8]map[FourTuple]*conn
	ports              map[uint8]map[uint16]*conn
	fromDownstream     chan *IPPacket
	toDownstream       chan *IPPacket
	fromUpstream       chan *IPPacket
	closedConns        chan *conn
	close              chan interface{}
}

// NewServer constructs a new Server that reads packets from downstream
// and writes response packets back to downstream.
func NewServer(downstream io.ReadWriter, opts *Opts) (Server, error) {
	err := opts.ApplyDefaults()
	if err != nil {
		return nil, errors.New("Error applying default options: %v", err)
	}

	log.Debugf("Outbound packets will use %v", opts.IFAddr)

	ctrack, err := ct.Dial(nil)
	if err != nil {
		return nil, errors.New("Unable to obtain connection for managing conntrack: %v", err)
	}
	_ctTimeout := opts.IdleTimeout * 2
	if _ctTimeout < MinConntrackTimeout {
		_ctTimeout = MinConntrackTimeout
	}
	ctTimeout := uint32(_ctTimeout.Seconds())

	// We create a random order for assigning new ports to minimize the chance of colliding
	// with other running gonat instances.
	randomPortSequence := make([]uint16, numEphemeralPorts)
	for i := uint16(0); i < uint16(numEphemeralPorts); i++ {
		randomPortSequence[i] = minEphemeralPort + i
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	rnd.Shuffle(numEphemeralPorts, func(i int, j int) {
		randomPortSequence[i], randomPortSequence[j] = randomPortSequence[j], randomPortSequence[i]
	})

	portIndexes := map[uint8]map[Addr]int{
		syscall.IPPROTO_TCP: make(map[Addr]int),
		syscall.IPPROTO_UDP: make(map[Addr]int),
	}
	conns := map[uint8]map[FourTuple]*conn{
		syscall.IPPROTO_TCP: make(map[FourTuple]*conn),
		syscall.IPPROTO_UDP: make(map[FourTuple]*conn),
	}
	ports := map[uint8]map[uint16]*conn{
		syscall.IPPROTO_TCP: make(map[uint16]*conn),
		syscall.IPPROTO_UDP: make(map[uint16]*conn),
	}

	s := &server{
		downstream:         downstream,
		opts:               opts,
		bufferPool:         opts.BufferPool,
		ctrack:             ctrack,
		ctTimeout:          ctTimeout,
		randomPortSequence: randomPortSequence,
		portIndexes:        portIndexes,
		conns:              conns,
		ports:              ports,
		fromDownstream:     make(chan *IPPacket, opts.BufferDepth),
		toDownstream:       make(chan *IPPacket, opts.BufferDepth),
		fromUpstream:       make(chan *IPPacket, opts.BufferDepth),
		closedConns:        make(chan *conn, opts.BufferDepth),
		close:              make(chan interface{}),
	}
	return s, nil
}

func (s *server) Serve() error {
	var err error
	s.tcpSocket, err = s.createSocket(syscall.IPPROTO_TCP, FourTuple{}, 0)
	if err != nil {
		return err
	}
	s.udpSocket, err = s.createSocket(syscall.IPPROTO_UDP, FourTuple{}, 0)
	if err != nil {
		return err
	}
	ops.Go(func() { s.readFromUpstream(s.tcpSocket) })
	ops.Go(func() { s.readFromUpstream(s.udpSocket) })

	ops.Go(s.trackStats)
	ops.Go(s.dispatch)
	ops.Go(s.writeToDownstream)
	return s.readFromDownstream()
}

func (s *server) dispatch() {
	defer s.ctrack.Close()

	reapTicker := time.NewTicker(1 * time.Second)
	defer reapTicker.Stop()

	for {
		select {
		case pkt := <-s.fromDownstream:
			s.onPacketFromDownstream(pkt)
		case pkt := <-s.fromUpstream:
			s.onPacketFromUpstream(pkt)
		case c := <-s.closedConns:
			s.deleteConn(c)
		case <-reapTicker.C:
			s.reapIdleConns()
		case <-s.close:
			for _, connsByFT := range s.conns {
				for _, c := range connsByFT {
					if c.timeSinceLastActive() > s.opts.IdleTimeout {
						c.Close()
						s.deleteConn(c)
					}
				}
			}
			s.tcpSocket.Close()
			s.udpSocket.Close()
			return
		}
	}
}

func (s *server) onPacketFromDownstream(pkt *IPPacket) {
	switch pkt.IPProto {
	case syscall.IPPROTO_TCP, syscall.IPPROTO_UDP:
		s.opts.OnOutbound(pkt)
		ft := pkt.FT()
		connsByFT := s.conns[pkt.IPProto]
		connsByPort := s.ports[pkt.IPProto]
		c := connsByFT[ft]

		if pkt.HasTCPFlag(TCPFlagRST) {
			if c != nil {
				c.Close()
			}
			return
		}

		if c == nil {
			port, err := s.assignPort(pkt, ft)
			if err != nil {
				log.Errorf("Unable to assign port, dropping packet %v: %v", ft, err)
				s.dropPacket(pkt)
				return
			}
			c, err = s.newConn(pkt.IPProto, ft, port)
			if err != nil {
				log.Errorf("Unable to create connection, dropping packet %v: %v", ft, err)
				s.dropPacket(pkt)
				return
			}
			connsByFT[ft] = c
			connsByPort[port] = c
			s.addConn(pkt.IPProto)
		}
		select {
		case c.toUpstream <- pkt:
			s.acceptedPacket()
		default:
			// don't block if we're stalled writing upstream
			log.Tracef("Stalled writing packet %v upstream", ft)
			s.dropPacket(pkt)
		}
	default:
		log.Tracef("Unknown IP protocol, ignoring packet %v: %v", pkt.FT(), pkt.IPProto)
		s.dropPacket(pkt)
	}
}

func (s *server) onPacketFromUpstream(pkt *IPPacket) {
	ft := pkt.FT()
	connsByPort := s.ports[pkt.IPProto]
	c := connsByPort[ft.Dst.Port]
	if c == nil {
		log.Tracef("Dropping packet for unknown port %v", ft)
		s.dropPacket(pkt)
		return
	}
	pkt.SetDest(c.ft.Src.IP, c.ft.Src.Port)
	c.s.opts.OnInbound(pkt, c.ft)
	pkt.recalcChecksum()
	c.s.acceptedPacket()
	c.markActive()
	c.s.toDownstream <- pkt
}

func (s *server) dropPacket(pkt *IPPacket) {
	s.rejectedPacket()
	s.bufferPool.Put(pkt.Raw)
}

// Since we're using unconnected raw sockets, the kernel doesn't create ip_conntrack
// entries for us. When we receive a SYNACK packet from the upstream end in response
// to the SYN packet that we forward from the client, the kernel automatically sends
// an RST packet because it doesn't see a connection in the right state. We can't
// actually fake a connection in the right state, however we can manually create an entry
// in ip_conntrack which allows us to use a single iptables rule to safely drop
// all outbound RST packets for tracked tcp connections. The rule can be added like so:
//
//   iptables -A OUTPUT -p tcp -m conntrack --ctstate ESTABLISHED --ctdir ORIGINAL --tcp-flags RST RST -j DROP
//
func (s *server) createConntrackEntry(ipProto uint8, ft FourTuple, port uint16) error {
	flow := s.ctFlowFor(true, ipProto, ft, port)
	log.Debugf("Creating conntrack entry for %v port %d", ft, port)
	return s.ctrack.Create(flow)
}

func (s *server) deleteConntrackEntry(ipProto uint8, ft FourTuple, port uint16) {
	flow := s.ctFlowFor(false, ipProto, ft, port)
	if err := s.ctrack.Delete(flow); err != nil {
		log.Errorf("Unable to delete conntrack entry for %v: %v", flow, err)
	}
}

func (s *server) ctFlowFor(create bool, ipProto uint8, ft FourTuple, port uint16) ct.Flow {
	srcIP := net.ParseIP(s.opts.IFAddr).To4()
	dstIP := net.ParseIP(ft.Dst.IP).To4()
	srcPort := port
	dstPort := ft.Dst.Port

	var ctTimeout uint32
	var status ct.StatusFlag
	if create {
		status = ct.StatusConfirmed | ct.StatusAssured
		ctTimeout = s.ctTimeout
	}

	flow := ct.NewFlow(
		ipProto, status,
		srcIP, dstIP,
		srcPort, dstPort,
		ctTimeout, 0)
	if create && ipProto == syscall.IPPROTO_TCP {
		flow.ProtoInfo.TCP = &ct.ProtoInfoTCP{
			State: 3, // ESTABLISHED
		}
	}

	return flow
}

// assignPort assigns an ephemeral local port for a new connection. If an existing connection
// with the resulting 4-tuple is already tracked because a different application created it,
// this will fail on createConntrackEntry and then retry until it finds an untracked ephemeral
// port or runs out of ports to try.
func (s *server) assignPort(pkt *IPPacket, ft FourTuple) (port uint16, err error) {
	portIndexesByOrigin := s.portIndexes[pkt.IPProto]
	for i := 0; i < numEphemeralPorts; i++ {
		portIndex := portIndexesByOrigin[ft.Dst] + 1
		if portIndex >= numEphemeralPorts {
			// loop back around to beginning of random sequence
			portIndex = 0
		}
		portIndexesByOrigin[ft.Dst] = portIndex
		port = s.randomPortSequence[portIndex]
		err = s.createConntrackEntry(pkt.IPProto, ft, port)
		if err != nil {
			// this can happen if this fourtuple is already tracked, ignore and retry
			continue
		}
		return
	}
	err = errors.New("Gave up looking for ephemeral port, final error from conntrack: %v", err)
	return
}

func (s *server) reapIdleConns() {
	var connsToClose []*conn
	for _, connsByFT := range s.conns {
		for _, c := range connsByFT {
			if c.timeSinceLastActive() > s.opts.IdleTimeout {
				connsToClose = append(connsToClose, c)
			}
		}
	}
	if len(connsToClose) > 0 {
		// close conns on a goroutine to avoid tying up main dispatch loop
		ops.Go(func() {
			for _, c := range connsToClose {
				c.Close()
			}
		})
	}
}

func (s *server) deleteConn(c *conn) {
	delete(s.conns[c.ipProto], c.ft)
	delete(s.ports[c.ipProto], c.port)
	s.deleteConntrackEntry(c.ipProto, c.ft, c.port)
}

// newConn creates a connection built around a raw socket for either TCP or UDP
// (depending no the specified proto). Being a raw socket, it allows us to send our
// own IP packets.
func (s *server) newConn(ipProto uint8, ft FourTuple, port uint16) (*conn, error) {
	socket, err := s.createSocket(ipProto, ft, port)
	if err != nil {
		return nil, err
	}
	c := &conn{
		ReadWriteCloser: socket,
		ipProto:         ipProto,
		ft:              ft,
		port:            port,
		toUpstream:      make(chan *IPPacket, s.opts.BufferDepth),
		s:               s,
		close:           make(chan interface{}),
	}
	ops.Go(c.writeToUpstream)
	return c, nil
}

func (s *server) createSocket(ipProto uint8, ft FourTuple, port uint16) (io.ReadWriteCloser, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, int(ipProto))
	if err != nil {
		return nil, errors.New("Unable to create transport: %v", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(fd)
		return nil, errors.New("Unable to set IP_HDRINCL: %v", err)
	}
	bindAddr := sockAddrFor(s.opts.IFAddr, port)
	if err := syscall.Bind(fd, bindAddr); err != nil {
		syscall.Close(fd)
		return nil, errors.New("Unable to bind raw socket: %v", err)
	}
	if ft.Dst.Port > 0 {
		connectAddr := sockAddrFor(ft.Dst.IP, ft.Dst.Port)
		if err := syscall.Connect(fd, connectAddr); err != nil {
			syscall.Close(fd)
			return nil, errors.New("Unable to connect raw socket: %v", err)
		}
	}
	if err := syscall.SetNonblock(fd, true); err != nil {
		syscall.Close(fd)
		return nil, errors.New("Unable to set raw socket to non-blocking: %v", err)
	}
	return os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd)), nil
}

func sockAddrFor(ip string, port uint16) syscall.Sockaddr {
	var addr [4]byte
	copy(addr[:], net.ParseIP(ip).To4())
	return &syscall.SockaddrInet4{
		Addr: addr,
		Port: int(port),
	}
}

type conn struct {
	io.ReadWriteCloser
	ipProto    uint8
	ft         FourTuple
	port       uint16
	toUpstream chan *IPPacket
	s          *server
	lastActive int64
	close      chan interface{}
}

func (c *conn) writeToUpstream() {
	defer func() {
		c.s.closedConns <- c
	}()
	defer c.ReadWriteCloser.Close()

	for {
		select {
		case pkt := <-c.toUpstream:
			pkt.SetSource(c.s.opts.IFAddr, c.port)
			pkt.recalcChecksum()
			_, err := c.Write(pkt.Raw)
			if err != nil {
				log.Errorf("Error writing upstream: %v", err)
				return
			}
			c.markActive()
		case <-c.close:
			return
		}
	}
}

func (c *conn) markActive() {
	atomic.StoreInt64(&c.lastActive, time.Now().UnixNano())
}

func (c *conn) timeSinceLastActive() time.Duration {
	return time.Duration(time.Now().UnixNano() - atomic.LoadInt64(&c.lastActive))
}

func (c *conn) Close() error {
	select {
	case <-c.close:
		return nil
	default:
		close(c.close)
		return nil
	}
}

// readFromDownstream reads all IP packets from downstream clients.
func (s *server) readFromDownstream() error {
	for {
		b := s.bufferPool.Get()
		n, err := s.downstream.Read(b)
		if err != nil {
			if err == io.EOF {
				return err
			}
			return errors.New("Unexpected error reading from downstream: %v", err)
		}
		raw := b[:n]
		pkt, err := parseIPPacket(raw)
		if err != nil {
			log.Tracef("Error on inbound packet, ignoring: %v", err)
			s.rejectedPacket()
			continue
		}
		s.fromDownstream <- pkt
	}
}

// writeToDownstream writes all IP packets that we're sending back dowstream.
func (s *server) writeToDownstream() {
	for pkt := range s.toDownstream {
		_, err := s.downstream.Write(pkt.Raw)
		s.bufferPool.Put(pkt.Raw)
		if err != nil {
			log.Errorf("Unexpected error writing to downstream: %v", err)
			return
		}
	}
}

func (s *server) readFromUpstream(socket io.ReadWriteCloser) {
	defer socket.Close()

	for {
		b := s.bufferPool.Get()
		n, err := socket.Read(b)
		if err != nil {
			s.rejectedPacket()
			s.bufferPool.Put(b)
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			return
		}
		if pkt, err := parseIPPacket(b[:n]); err != nil {
			log.Tracef("Dropping unparseable packet from upstream: %v", err)
			s.rejectedPacket()
			s.bufferPool.Put(b)
		} else {
			s.fromUpstream <- pkt
		}
	}
}

func (s *server) Close() error {
	select {
	case <-s.close:
		// already closed
		return nil
	default:
		close(s.close)
		return nil
	}
}
