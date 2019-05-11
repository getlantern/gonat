package gonat

import (
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/getlantern/errors"
	"github.com/getlantern/golog"
	"github.com/oxtoacart/bpool"
)

const (
	// DefaultMTU is 60000 to accomodate large segments
	DefaultMTU = 60000

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

	downstream io.ReadWriter
	opts       *Opts
	bufferPool *bpool.BytePool
	// udpTransport io.ReadWriteCloser
	tcpTransport    *transport
	fromDownstream  chan *ipPacket
	toUpstreamTCP   chan *ipPacket
	fromUpstreamTCP chan *ipPacket
	toDownstream    chan *ipPacket
	close           chan interface{}
}

type conn struct {
	io.Closer
	port uint16
}

type Opts struct {
	// IFAddr is the address of the interface to use for connecting upstream
	IFAddr string

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

	onOutbound func(pkt *ipPacket)

	onInbound func(pkt *ipPacket)
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
	if opts.onOutbound == nil {
		opts.onOutbound = func(pkt *ipPacket) {}
	}
	if opts.onInbound == nil {
		opts.onInbound = func(pkt *ipPacket) {}
	}
	return opts
}

func NewServer(downstream io.ReadWriter, opts *Opts) (Server, error) {
	opts.ApplyDefaults()

	tcpTransport, err := createTransport(syscall.IPPROTO_TCP)
	if err != nil {
		return nil, errors.New("Unable to create TCP transport: %v", err)
	}
	s := &server{
		downstream:      downstream,
		opts:            opts,
		bufferPool:      bpool.NewBytePool(opts.BufferPoolSize/opts.MTU, opts.MTU),
		tcpTransport:    tcpTransport,
		fromDownstream:  make(chan *ipPacket, 2500),
		toUpstreamTCP:   make(chan *ipPacket, 2500),
		fromUpstreamTCP: make(chan *ipPacket, 2500),
		toDownstream:    make(chan *ipPacket, 2500),
		close:           make(chan interface{}),
	}
	return s, nil
}

func (s *server) Serve() error {
	go s.trackStats()
	go s.dispatch()
	go s.writeToUpstreamTCP()
	go s.readFromUpstreamTCP()
	go s.writeToDownstream()
	return s.readFromDownstream()
}

func (s *server) dispatch() {
	reapTicker := time.NewTicker(1 * time.Second)
	defer reapTicker.Stop()

	tcpConns := make(map[fourtuple]*conn)
	tcpPorts := make(map[uint16]fourtuple)
	for {
		select {
		case pkt := <-s.fromDownstream:
			switch pkt.ipProto {
			case syscall.IPPROTO_TCP:
				ft := pkt.ft()
				c := tcpConns[ft]
				if c == nil {
					// In order to keep the kernel from sending RST packets in response to packets from upstream,
					// we need to bind a TCP socket. We'll never actually read from this socket, but we use its
					// port to uniquely identify this TCP connection. We close the socket when we're finished with this
					// connection.
					socket, port, err := s.bindTCPSocket()
					if err != nil {
						log.Errorf("Unable to reserve tcp port, dropping packet: %v", err)
						continue
					}
					socket.Close()
					c = &conn{
						Closer: socket,
						port:   port,
					}
					tcpConns[ft] = c
					tcpPorts[port] = ft
					s.addTCPConn()
				}
				pkt.setDest("80.249.99.148", 80)
				pkt.setSource(s.opts.IFAddr, c.port)
				pkt.recalcTCPChecksum()
				pkt.recalcIPChecksum()
				s.acceptedPacket()
				s.toUpstreamTCP <- pkt
			default:
				s.rejectedPacket()
				log.Tracef("Unknown IP protocol, ignoring: %v", pkt.ipProto)
				continue
			}
		case pkt := <-s.fromUpstreamTCP:
			port := pkt.ft().dst.port
			ft, found := tcpPorts[port]
			if !found {
				s.rejectedPacket()
				log.Tracef("Unknown connection, dropping response packet: %d", port)
				continue
			}
			pkt.setDest(ft.src.ip, ft.src.port)
			pkt.setSource("10.0.0.1", ft.dst.port)
			pkt.recalcTCPChecksum()
			pkt.recalcIPChecksum()
			s.acceptedPacket()
			s.toDownstream <- pkt
		case <-reapTicker.C:
			// p.reapTCP()
			// p.reapUDP()
		case <-s.close:
			return
		}
	}
}

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

func (s *server) readFromUpstreamTCP() {
	for {
		b := s.bufferPool.Get()
		n, err := s.tcpTransport.Read(b)
		if err != nil {
			log.Errorf("Unexpected error reading from upstream: %v", err)
			return
		}
		log.Tracef("Read %d from upstream", n)
		raw := b[:n]
		pkt, err := parseIPPacket(raw)
		if err != nil {
			log.Debugf("Error on inbound packet, ignoring: %v", err)
			// p.rejectedPacket()
			continue
		}
		s.fromUpstreamTCP <- pkt
	}
}

func (s *server) writeToDownstream() {
	for pkt := range s.toDownstream {
		_, err := s.downstream.Write(pkt.raw)
		s.bufferPool.Put(pkt.raw)
		if err != nil {
			log.Errorf("Unexpected error writing to downstream: %v", err)
			return
		}
	}
}

func (s *server) writeToUpstreamTCP() {
	for pkt := range s.toUpstreamTCP {
		err := s.tcpTransport.Write(pkt)
		s.bufferPool.Put(pkt.raw)
		if err != nil {
			log.Errorf("Unexpected error writing to upstream TCP: %v", err)
			return
		}
	}
}

func (s *server) Close() error {
	return nil
}

func createTransport(proto int) (*transport, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
	if err != nil {
		return nil, errors.New("Unable to create transport: %v", err)
	}
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return nil, errors.New("Unable to set IP_HDRINCL: %v", err)
	}
	if err := syscall.BindToDevice(fd, "wlp107s0"); err != nil {
		return nil, errors.New("Unable to bind to interface: %v", err)
	}
	err = unix.SetNonblock(fd, true)
	if err != nil {
		return nil, errors.New("Unable to set non-blocking: %v", err)
	}
	file := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
	tr := &transport{
		ReadCloser: file,
		fd:         fd,
	}
	return tr, nil
}

func (s *server) bindTCPSocket() (io.Closer, uint16, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, 0, errors.New("Unable to create TCP socket: %v", err)
	}
	var addr [4]byte
	copy(addr[:], net.ParseIP(s.opts.IFAddr).To4())
	bindAddr := &syscall.SockaddrInet4{
		Addr: addr,
		Port: 0, // let OS pick a port for us
	}
	if err := syscall.Bind(fd, bindAddr); err != nil {
		return nil, 0, errors.New("Unable to bind TCP socket: %v", err)
	}
	// if err := syscall.Listen(fd, 1000); err != nil {
	// 	return nil, 0, errors.New("Unable to listen on bound TCP socket: %v", err)
	// }
	sa, err := syscall.Getsockname(fd)
	if err != nil {
		return nil, 0, errors.New("Unable to get bound TCP socket address: %v", err)
	}
	file := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))
	return file, uint16(sa.(*syscall.SockaddrInet4).Port), nil
}

type transport struct {
	io.ReadCloser
	fd int
}

func (tr *transport) Write(pkt *ipPacket) error {
	var addr [4]byte
	copy(addr[:], pkt.dstAddr.IP.To4())
	sockAddr := &unix.SockaddrInet4{Port: int(pkt.ft().dst.port), Addr: addr}
	return unix.Sendto(tr.fd, pkt.raw, 0, sockAddr)
}
