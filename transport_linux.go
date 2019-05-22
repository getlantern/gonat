package gonat

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/getlantern/errors"
	"github.com/getlantern/ops"
)

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
