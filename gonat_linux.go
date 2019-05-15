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

	"github.com/getlantern/errors"
	"github.com/getlantern/golog"
	"github.com/oxtoacart/bpool"
)

const (
	// DefaultMTU is 65536 to accomodate large segments
	DefaultMTU = 65536

	// DefaultBufferPoolSize is 10 MB
	DefaultBufferPoolSize = 10000000

	// DefaultBufferDepth is 250 packets
	DefaultBufferDepth = 250

	// DefaultIdleTimeout is 65 seconds
	DefaultIdleTimeout = 65 * time.Second

	// DefaultStatsInterval is 15 seconds
	DefaultStatsInterval = 15 * time.Second
)

const (
	minEphemeralPort = 32768
	maxEphemeralPort = 61000 // consistent with most Linux kernels
)

var (
	log = golog.LoggerFor("gonat")
)

type Server interface {
	// Serve starts processing packets and blocks until finished
	Serve() error

	// Count of accepted packets
	AcceptedPackets() int

	// Count of rejected packets
	RejectedPackets() int

	// Number of TCP connections being tracked
	NumTCPConns() int

	// Number of UDP connections being tracked
	NumUDPConns() int

	// Close stops the server and cleans up resources
	Close() error
}

type server struct {
	acceptedPackets int64
	rejectedPackets int64
	numTCPConns     int64
	numUDPConns     int64

	downstream     io.ReadWriter
	opts           *Opts
	ifAddr         string
	bufferPool     *bpool.BytePool
	fromDownstream chan *IPPacket
	toDownstream   chan *IPPacket
	close          chan interface{}
}

type Opts struct {
	// IFName is the name of the interface to use for connecting upstream
	IFName string

	// MTU in bytes. Default of 1500 is usually fine.
	MTU int

	// BufferPoolSize is the size of the buffer pool in bytes
	BufferPoolSize int

	// BufferDepth specifies the number of outbound packets to buffer between
	// stages in the send/receive pipeline. The default is 250.
	BufferDepth int

	// IdleTimeout specifies the amount of time before idle connections are
	// automatically closed. The default is 65 seconds.
	IdleTimeout time.Duration

	// StatsInterval controls how frequently to display stats. Defaults to 15
	// seconds.
	StatsInterval time.Duration

	// OnOutbound allows modifying outbound ip packets.
	OnOutbound func(pkt *IPPacket)

	// OnInbound allows modifying inbound ip packets. ft is the fourtuple to
	// which the current connection/UDP port mapping is keyed.
	OnInbound func(pkt *IPPacket, ft FourTuple)
}

// ApplyDefaults applies the default values to the given Opts, including making
// a new Opts if opts is nil.
func (opts *Opts) ApplyDefaults() *Opts {
	if opts == nil {
		opts = &Opts{}
	}
	if opts.MTU <= 0 {
		opts.MTU = DefaultMTU
	}
	if opts.BufferPoolSize <= 0 {
		opts.BufferPoolSize = DefaultBufferPoolSize
	}
	if opts.BufferDepth <= 0 {
		opts.BufferDepth = DefaultBufferDepth
	}
	if opts.IdleTimeout <= 0 {
		opts.IdleTimeout = DefaultIdleTimeout
	}
	if opts.StatsInterval <= 0 {
		opts.StatsInterval = DefaultStatsInterval
	}
	if opts.OnOutbound == nil {
		opts.OnOutbound = func(pkt *IPPacket) {}
	}
	if opts.OnInbound == nil {
		opts.OnInbound = func(pkt *IPPacket, ft FourTuple) {}
	}
	return opts
}

func NewServer(downstream io.ReadWriter, opts *Opts) (Server, error) {
	opts.ApplyDefaults()

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
	log.Debugf("Outbound packets will use %v", ifAddr)

	s := &server{
		downstream:     downstream,
		opts:           opts,
		ifAddr:         ifAddr,
		bufferPool:     bpool.NewBytePool(opts.BufferPoolSize/opts.MTU, opts.MTU),
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

func (s *server) dispatch() {
	reapTicker := time.NewTicker(1 * time.Second)
	defer reapTicker.Stop()

	conns := map[uint8]map[FourTuple]*conn{
		syscall.IPPROTO_TCP: make(map[FourTuple]*conn),
		syscall.IPPROTO_UDP: make(map[FourTuple]*conn),
	}

	// Since we're using unconnected raw sockets, the kernel doesn't create ip_conntrack
	// entries for us. When we receive a SYN,ACK packet from the upstream end in response
	// to the SYN packet that we forward from the client, the kernel automatically sends
	// an RST packet because it doesn't see a connection in the right state. We can't
	// actually fake a connection in the right state, however we can manually create an "ESTABLISHED"
	// connection in ip_conntrack which allows us to use a single iptables rule to safely drop
	// all outbound RST packets for such connections. The rule can be added like so:
	//
	//   iptables -A OUTPUT -p tcp -m conntrack --ctstate ESTABLISHED --ctdir ORIGINAL --tcp-flags RST RST -j DROP
	//
	createConntrackEntry := func(pkt *IPPacket, ft FourTuple, port uint16) error {
		srcIP := s.ifAddr
		dstIP := ft.Dst.IP
		srcPort := strconv.Itoa(int(port))
		dstPort := strconv.Itoa(int(ft.Dst.Port))
		srcIP, dstIP = dstIP, srcIP
		// srcPort, dstPort = dstPort, srcPort

		proto := ""
		switch pkt.IPProto {
		case syscall.IPPROTO_TCP:
			proto = "TCP"
		case syscall.IPPROTO_UDP:
			proto = "UDP"
		}
		args := []string{
			"-I", "-u", "ASSURED",
			"--timeout", strconv.Itoa(int(s.opts.IdleTimeout.Seconds())),
			"-p", proto,
			"-s", srcIP, "-d", dstIP,
			"-r", dstIP, "-q", srcIP,
			"--sport", srcPort, "--dport", dstPort,
			"--reply-port-src", dstPort, "--reply-port-dst", srcPort,
		}

		if pkt.IPProto == syscall.IPPROTO_TCP {
			args = append(args, "--state", "ESTABLISHED")
		}

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
	rand.Shuffle(numEphemeralPorts, func(i int, j int) {
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
