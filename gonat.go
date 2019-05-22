package gonat

import (
	"net"
	"time"

	"github.com/getlantern/errors"
	"github.com/getlantern/golog"
	"github.com/oxtoacart/bpool"
)

const (
	// DefaultBufferPoolSize is 10 MB
	DefaultBufferPoolSize = 10000000

	// DefaultBufferDepth is 250 packets
	DefaultBufferDepth = 250

	// DefaultIdleTimeout is 65 seconds
	DefaultIdleTimeout = 65 * time.Second

	// DefaultStatsInterval is 15 seconds
	DefaultStatsInterval = 15 * time.Second

	// MinConntrackTimeout sets a lower bound on how long we'll let conntrack entries persist
	MinConntrackTimeout = 1 * time.Minute

	// MaximumIPPacketSize is 65535 bytes
	MaximumIPPacketSize = 65535
)

const (
	minEphemeralPort  = 32768
	maxEphemeralPort  = 61000 // consistent with most Linux kernels
	numEphemeralPorts = maxEphemeralPort - minEphemeralPort
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

type Opts struct {
	// IFName is the name of the interface to use for connecting upstream.
	// If not specified, this will use the default interface for reaching the
	// Internet.
	IFName string

	// IFAddr is the address to use for outbound packets. Overrides the IFName
	// when specified.
	IFAddr string

	// BufferPool is a pool for buffers. If not provided, default to a 10MB pool.
	// Each []byte in the buffer pool should be 65536 bytes.
	BufferPool BufferPool

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
func (opts *Opts) ApplyDefaults() error {
	if opts == nil {
		opts = &Opts{}
	}
	if opts.BufferPool == nil {
		opts.BufferPool = NewBufferPool(DefaultBufferPoolSize)
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
	if opts.IFAddr == "" {
		var err error
		if opts.IFName != "" {
			opts.IFAddr, err = firstIPv4AddrFor(opts.IFName)
		} else {
			opts.IFAddr, err = findDefaultIPv4Addr()
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func firstIPv4AddrFor(ifName string) (string, error) {
	outIF, err := net.InterfaceByName(ifName)
	if err != nil {
		return "", errors.New("Unable to find interface for interface %v: %v", ifName, err)
	}
	outIFAddrs, err := outIF.Addrs()
	if err != nil {
		return "", errors.New("Unable to get addresses for interface %v: %v", ifName, err)
	}
	for _, outIFAddr := range outIFAddrs {
		switch t := outIFAddr.(type) {
		case *net.IPNet:
			ipv4 := t.IP.To4()
			if ipv4 != nil {
				return ipv4.String(), nil
			}
		}
	}
	return "", errors.New("Unable to find IPv4 address for interface %v", ifName)
}

func findDefaultIPv4Addr() (string, error) {
	// try to find default interface by dialing an external connection
	conn, err := net.Dial("udp4", "lantern.io:80")
	if err != nil {
		return "", errors.New("Unable to dial lantern.io: %v", err)
	}
	ip := conn.LocalAddr().(*net.UDPAddr).IP.String()
	return ip, nil
}

// NewBufferPool creates a buffer pool with the given sizeInBytes containing slices
// sized to accomodate our MaximumIPPacketSize.
func NewBufferPool(sizeInBytes int) BufferPool {
	return bpool.NewBytePool(sizeInBytes, MaximumIPPacketSize)
}

// BufferPool is a bool of byte slices
type BufferPool interface {
	// Get gets a byte slice from the pool
	Get() []byte
	// Put returns a byte slice to the pool
	Put([]byte)
}
