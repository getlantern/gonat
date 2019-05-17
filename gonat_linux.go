package gonat

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"time"

	ct "github.com/florianl/go-conntrack"
	"github.com/getlantern/errors"
	"github.com/mdlayher/netlink/nlenc"
)

type server struct {
	acceptedPackets int64
	rejectedPackets int64
	numTCPConns     int64
	numUDPConns     int64

	downstream     io.ReadWriter
	opts           *Opts
	ifAddr         string
	bufferPool     BufferPool
	fromDownstream chan *IPPacket
	toDownstream   chan *IPPacket
	close          chan interface{}
}

// NewServer constructs a new Server that reads packets from downstream
// and writes response packets back to downstream.
func NewServer(downstream io.ReadWriter, opts *Opts) (Server, error) {
	err := opts.ApplyDefaults()
	if err != nil {
		return nil, errors.New("Error applying default options: %v", err)
	}

	outIF, err := net.InterfaceByName(opts.IFName)
	if err != nil {
		return nil, errors.New("Unable to find interface for interface %v: %v", opts.IFName, err)
	}
	outIFAddrs, err := outIF.Addrs()
	if err != nil {
		return nil, errors.New("Unable to get addresses for interface %v: %v", opts.IFName, err)
	}
	ifAddr := ""
	for _, outIFAddr := range outIFAddrs {
		log.Debugf("Checking %v", outIFAddr)
		switch t := outIFAddr.(type) {
		case *net.IPNet:
			ipv4 := t.IP.To4()
			if ipv4 != nil {
				ifAddr = ipv4.String()
				break
			}
		}
	}
	if ifAddr == "" {
		return nil, errors.New("Unable to find IPv4 address for interface %v", opts.IFName)
	}
	log.Debugf("Outbound packets will use %v on %v", ifAddr, opts.IFName)

	s := &server{
		downstream:     downstream,
		opts:           opts,
		ifAddr:         ifAddr,
		bufferPool:     opts.BufferPool,
		fromDownstream: make(chan *IPPacket, 2500),
		toDownstream:   make(chan *IPPacket, 2500),
		close:          make(chan interface{}),
	}
	return s, nil
}

func (s *server) Serve() error {
	go s.trackStats()
	go s.dispatch()
	go s.writeToDownstream()
	return s.readFromDownstream()
}

func ctAttr(t ct.ConnAttrType, d []byte) ct.ConnAttr {
	return ct.ConnAttr{Type: t, Data: d}
}

func (s *server) dispatch() {
	reapTicker := time.NewTicker(1 * time.Second)
	defer reapTicker.Stop()

	conns := map[uint8]map[FourTuple]*conn{
		syscall.IPPROTO_TCP: make(map[FourTuple]*conn),
		syscall.IPPROTO_UDP: make(map[FourTuple]*conn),
	}

	ctrack, err := ct.Open(&ct.Config{})
	if err != nil {
		log.Errorf("Unable to create conntrack connection: %v", err)
		return
	}
	defer ctrack.Close()

	ctTimeout := s.opts.IdleTimeout * 2
	if ctTimeout < MinConntrackTimeout {
		ctTimeout = MinConntrackTimeout
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
	createConntrackEntry := func(pkt *IPPacket, ft FourTuple, port uint16) error {
		srcIP := net.ParseIP(s.ifAddr).To4()
		dstIP := pkt.DstAddr.IP.To4()
		srcPort := nlenc.Uint16Bytes(port)
		dstPort := nlenc.Uint16Bytes(ft.Dst.Port)
		srcIP, dstIP = dstIP, srcIP

		attrs := []ct.ConnAttr{
			ctAttr(ct.AttrOrigIPv4Src, srcIP),
			ctAttr(ct.AttrOrigIPv4Dst, dstIP),
			ctAttr(ct.AttrReplIPv4Src, dstIP),
			ctAttr(ct.AttrReplIPv4Dst, srcIP),
			ctAttr(ct.AttrOrigL4Proto, nlenc.Uint8Bytes(pkt.IPProto)),
			ctAttr(ct.AttrReplL4Proto, nlenc.Uint8Bytes(pkt.IPProto)),
			ctAttr(ct.AttrOrigPortSrc, srcPort),
			ctAttr(ct.AttrOrigPortDst, dstPort),
			ctAttr(ct.AttrReplPortSrc, dstPort),
			ctAttr(ct.AttrReplPortDst, srcPort),
			ctAttr(ct.AttrStatus, nlenc.Uint32Bytes(2382430208)),
			ctAttr(ct.AttrTimeout, nlenc.Uint32Bytes(uint32(ctTimeout.Seconds()))),
		}

		if pkt.IPProto == syscall.IPPROTO_TCP {
			attrs = append(attrs, ctAttr(ct.AttrTCPState, nlenc.Uint8Bytes(3))) // ESTABLISHED
		}

		log.Debugf("Creating conntrack entry for %d %v:%v -> %v:%v", pkt.IPProto, srcIP, nlenc.Uint16(srcPort), dstIP, nlenc.Uint16(dstPort))
		return ctrack.Create(ct.Ct, ct.CtIPv4, attrs)
	}

	// For now, we use the conntrack command since the library doesn't seem to work for TCP
	createConntrackEntry = func(pkt *IPPacket, ft FourTuple, port uint16) error {
		srcIP := s.ifAddr
		dstIP := ft.Dst.IP
		srcPort := strconv.Itoa(int(port))
		dstPort := strconv.Itoa(int(ft.Dst.Port))
		srcIP, dstIP = dstIP, srcIP

		proto := ""
		switch pkt.IPProto {
		case syscall.IPPROTO_TCP:
			proto = "TCP"
		case syscall.IPPROTO_UDP:
			proto = "UDP"
		}

		args := []string{
			"-I", "-u", "ASSURED",
			"--timeout", strconv.Itoa(int(ctTimeout.Seconds())),
			"-p", proto,
			"-s", srcIP, "-d", dstIP,
			"-r", dstIP, "-q", srcIP,
			"--sport", srcPort, "--dport", dstPort,
			"--reply-port-src", dstPort, "--reply-port-dst", srcPort,
		}

		if pkt.IPProto == syscall.IPPROTO_TCP {
			args = append(args, "--state", "ESTABLISHED")
		}

		log.Debugf("Creating conntrack entry for %v", args)
		cmd := exec.Command("conntrack", args...)
		err := cmd.Run()
		if err != nil {
			err = errors.New("Unable to add conntrack entry with args %v: %v", args, err)
		}
		return err
	}

	// We create a random order for assigning new ports to minimize the chance of colliding
	// with other running gonat instances.
	numEphemeralPorts := maxEphemeralPort - minEphemeralPort
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

	// assignPort assigns an ephemeral local port for a new connection. If an existing connection
	// with the resulting 4-tuple is already tracked because a different application created it,
	// this will fail on createConntrackEntry and then retry until it finds an untracked ephemeral
	// port or runs out of ports to try.
	assignPort := func(pkt *IPPacket, ft FourTuple) (port uint16, err error) {
		portIndexesByOrigin := portIndexes[pkt.IPProto]
		for i := 0; i < numEphemeralPorts; i++ {
			portIndex := portIndexesByOrigin[ft.Dst] + 1
			if portIndex >= numEphemeralPorts {
				// loop back around to beginning of random sequence
				portIndex = 0
			}
			portIndexesByOrigin[ft.Dst] = portIndex
			port = randomPortSequence[portIndex]
			err = createConntrackEntry(pkt, ft, port)
			if err != nil {
				// this can happen if this fourtuple is already tracked, ignore and retry
				continue
			}
			return
		}
		err = errors.New("Gave up looking for ephemeral port, final error from conntrack: %v", err)
		return
	}

	for {
		select {
		case pkt := <-s.fromDownstream:
			switch pkt.IPProto {
			case syscall.IPPROTO_TCP, syscall.IPPROTO_UDP:
				s.opts.OnOutbound(pkt)
				ft := pkt.FT()
				connsByFT := conns[pkt.IPProto]
				c := connsByFT[ft]
				if c == nil {
					port, err := assignPort(pkt, ft)
					if err != nil {
						log.Errorf("Unable to assign port, dropping packet: %v", err)
						s.rejectedPacket()
						s.bufferPool.Put(pkt.Raw)
						continue
					}
					c, err = s.newConn(pkt.IPProto, ft, port)
					if err != nil {
						log.Errorf("Unable to create connection, dropping packet: %v", err)
						s.rejectedPacket()
						s.bufferPool.Put(pkt.Raw)
						continue
					}
					connsByFT[ft] = c
					s.addConn(pkt.IPProto)
				}
				s.acceptedPacket()
				c.toUpstream <- pkt
			default:
				s.rejectedPacket()
				s.bufferPool.Put(pkt.Raw)
				log.Tracef("Unknown IP protocol, ignoring: %v", pkt.IPProto)
				continue
			}
		case <-reapTicker.C:
			// p.reapTCP()
			// p.reapUDP()
		case <-s.close:
			return
		}
	}
}

// newConn creates a connection built around a raw socket for either TCP or UDP
// (depending no the specified proto). Being a raw socket, it allows us to send our
// own IP packets.
func (s *server) newConn(proto uint8, ft FourTuple, port uint16) (*conn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, int(proto))
	if err != nil {
		return nil, errors.New("Unable to create transport: %v", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return nil, errors.New("Unable to set IP_HDRINCL: %v", err)
	}
	bindAddr := sockAddrFor(s.ifAddr, port)
	if err := syscall.Bind(fd, bindAddr); err != nil {
		return nil, errors.New("Unable to bind raw socket: %v", err)
	}
	connectAddr := sockAddrFor(ft.Dst.IP, ft.Dst.Port)
	if err := syscall.Connect(fd, connectAddr); err != nil {
		return nil, errors.New("Unable to connect raw socket: %v", err)
	}
	file := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
	c := &conn{
		ReadWriteCloser: file,
		port:            port,
		ft:              ft,
		toUpstream:      make(chan *IPPacket, s.opts.BufferDepth),
		s:               s,
	}
	go c.readFromUpstream()
	go c.writeToUpstream()
	return c, nil
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
	ft         FourTuple
	port       uint16
	toUpstream chan *IPPacket
	s          *server
}

func (c *conn) writeToUpstream() {
	for pkt := range c.toUpstream {
		pkt.SetSource(c.s.ifAddr, c.port)
		pkt.recalcChecksum()
		_, err := c.Write(pkt.Raw)
		if err != nil {
			log.Errorf("Error writing upstream: %v", err)
			return
		}
	}
}

func (c *conn) readFromUpstream() {
	for {
		b := c.s.bufferPool.Get()
		n, err := c.Read(b)
		if err != nil {
			c.s.rejectedPacket()
			c.s.bufferPool.Put(b)
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				continue
			}
			return
		}
		if pkt, err := parseIPPacket(b[:n]); err != nil {
			c.s.rejectedPacket()
			c.s.bufferPool.Put(b)
		} else {
			pkt.SetDest(c.ft.Src.IP, c.ft.Src.Port)
			c.s.opts.OnInbound(pkt, c.ft)
			pkt.recalcChecksum()
			c.s.acceptedPacket()
			c.s.toDownstream <- pkt
		}
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

func (s *server) Close() error {
	return nil
}
