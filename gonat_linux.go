package gonat

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/coreos/go-iptables/iptables"
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

	// Number of UDP ports being tracked
	NumUDPPorts() int

	// Close stops the server and cleans up resources
	Close() error
}

type server struct {
	acceptedPackets int64
	rejectedPackets int64
	numTcpConns     int64
	numUdpPorts     int64

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

	ipt, err := iptables.NewWithProtocol(iptables.ProtocolIPv4)
	if err != nil {
		log.Errorf("Unable to prepare iptables: %v", err)
		return
	}
	tcpConns := make(map[FourTuple]*conn)
	for {
		select {
		case pkt := <-s.fromDownstream:
			switch pkt.IPProto {
			case syscall.IPPROTO_TCP:
				s.opts.OnOutbound(pkt)
				ft := pkt.FT()
				c := tcpConns[ft]
				if c == nil {
					var err error
					c, err = s.newConn(pkt.IPProto, ft)
					if err != nil {
						log.Errorf("Unable to reserve tcp port, dropping packet: %v", err)
						s.rejectedPacket()
						s.bufferPool.Put(pkt.Raw)
						continue
					}
					tcpConns[ft] = c
					s.addTCPConn()
					// Drop RST packets originating from our ephemeral port so that when the kernel automatically
					// generates an RST in response to the unexpected SYN,ACK from upstream, we don't actually
					// kill the connection.
					// TODO: remove this rule when we're done with this ephemeral port and make sure that a final RST does get sent.
					if err := ipt.Append("filter", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "--source", s.ifAddr, "--source-port", strconv.Itoa(int(c.port)), "-j", "DROP"); err != nil {
						log.Errorf("Error updating iptables: %v", err)
					}
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

// newConn creates a connection built around a raw socket for either TCP or UDP
// (depending no the specified proto). Being a raw socket, it allows us to send our
// own IP packets.
func (s *server) newConn(proto uint8, ft FourTuple) (*conn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, int(proto))
	if err != nil {
		return nil, errors.New("Unable to create transport: %v", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return nil, errors.New("Unable to set IP_HDRINCL: %v", err)
	}
	bindAddr := sockAddrFor(s.ifAddr, 0)
	if err := syscall.Bind(fd, bindAddr); err != nil {
		return nil, errors.New("Unable to bind raw socket: %v", err)
	}
	connectAddr := sockAddrFor(ft.Dst.IP, ft.Dst.Port)
	if err := syscall.Connect(fd, connectAddr); err != nil {
		return nil, errors.New("Unable to connect raw socket: %v", err)
	}
	file := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		return nil, errors.New("Unable to get bound TCP socket address: %v", err)
	}
	c := &conn{
		ReadWriteCloser: file,
		port:            uint16(sa.(*syscall.SockaddrInet4).Port),
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
		pkt.recalcTCPChecksum()
		pkt.recalcIPChecksum()
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
			pkt.recalcTCPChecksum()
			pkt.recalcIPChecksum()
			c.s.acceptedPacket()
			c.s.toDownstream <- pkt
		}
	}
}
