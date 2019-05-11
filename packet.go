// Checksum computations based on logic in github.com/google/gopacket
//
// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.

package gonat

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/getlantern/errors"
)

var (
	networkByteOrder = binary.BigEndian
)

func parseIPPacket(raw []byte) (*ipPacket, error) {
	ipVersion := uint8(raw[0]) >> 4
	if ipVersion != 4 {
		return nil, errors.New("Unsupported ip protocol version: %v", ipVersion)
	}

	pkt := &ipPacket{raw: raw, ipVersion: ipVersion}
	return pkt.parseV4()
}

type ipPacket struct {
	raw       []byte
	ipVersion uint8
	ipProto   uint8
	srcAddr   *net.IPAddr
	dstAddr   *net.IPAddr
	header    []byte
	payload   []byte
}

func (pkt *ipPacket) parseV4() (*ipPacket, error) {
	ihl := uint8(pkt.raw[0]) & 0x0F
	length := networkByteOrder.Uint16(pkt.raw[2:4])
	if length < 20 {
		return pkt, errors.New("Invalid (too small) IP length (%d < 20)", length)
	} else if ihl < 5 {
		return pkt, errors.New("Invalid (too small) IP header length (%d < 5)", ihl)
	} else if int(ihl*4) > int(length) {
		return pkt, errors.New("Invalid IP header length > IP length (%d > %d)", ihl, length)
	} else if int(ihl)*4 > len(pkt.raw) {
		return pkt, errors.New("Not all IP header bytes available")
	}

	pkt.header = pkt.raw[:ihl*4]
	pkt.payload = pkt.raw[ihl*4:]
	pkt.ipProto = uint8(pkt.header[9])
	pkt.srcAddr = &net.IPAddr{IP: net.IP(pkt.header[12:16])}
	pkt.dstAddr = &net.IPAddr{IP: net.IP(pkt.header[16:20])}

	return pkt, nil
}

func (pkt *ipPacket) ft() fourtuple {
	return fourtuple{
		src: addr{ip: pkt.srcAddr.String(), port: networkByteOrder.Uint16(pkt.payload[0:2])},
		dst: addr{ip: pkt.dstAddr.String(), port: networkByteOrder.Uint16(pkt.payload[2:4])},
	}
}

func (pkt *ipPacket) setSource(host string, port uint16) {
	copy(pkt.header[12:16], net.ParseIP(host).To4())
	networkByteOrder.PutUint16(pkt.payload[0:2], port)
	pkt.srcAddr = &net.IPAddr{IP: net.IP(pkt.header[12:16])}
}

func (pkt *ipPacket) setDest(host string, port uint16) {
	copy(pkt.header[16:20], net.ParseIP(host).To4())
	networkByteOrder.PutUint16(pkt.payload[2:4], port)
	pkt.dstAddr = &net.IPAddr{IP: net.IP(pkt.header[16:20])}
}

func (pkt *ipPacket) ipChecksum() uint16 {
	return networkByteOrder.Uint16(pkt.header[10:])
}

func (pkt *ipPacket) recalcIPChecksum() {
	// Clear checksum bytes
	pkt.header[10] = 0
	pkt.header[11] = 0

	// Compute checksum
	var csum uint32
	for i := 0; i < len(pkt.header); i += 2 {
		csum += uint32(pkt.header[i]) << 8
		csum += uint32(pkt.header[i+1])
	}
	for {
		// Break when sum is less or equals to 0xFFFF
		if csum <= 65535 {
			break
		}
		// Add carry to the sum
		csum = (csum >> 16) + uint32(uint16(csum))
	}
	// Flip all the bits
	networkByteOrder.PutUint16(pkt.header[10:], ^uint16(csum))
}

func (pkt *ipPacket) tcpChecksum() uint16 {
	return networkByteOrder.Uint16(pkt.payload[16:])
}

func (pkt *ipPacket) recalcTCPChecksum() {
	// Clear checksum bytes
	pkt.payload[16] = 0
	pkt.payload[17] = 0

	csum := pkt.calcIPPseudoHeaderChecksum()

	// to handle odd lengths, we loop to length - 1, incrementing by 2, then
	// handle the last byte specifically by checking against the original
	// length.
	length := len(pkt.payload) - 1
	for i := 0; i < length; i += 2 {
		// For our test packet, doing this manually is about 25% faster
		// (740 ns vs. 1000ns) than doing it by calling binary.BigEndian.Uint16.
		csum += uint32(pkt.payload[i]) << 8
		csum += uint32(pkt.payload[i+1])
	}
	if len(pkt.payload)%2 == 1 {
		csum += uint32(pkt.payload[length]) << 8
	}
	for csum > 0xffff {
		csum = (csum >> 16) + (csum & 0xffff)
	}
	networkByteOrder.PutUint16(pkt.payload[16:], ^uint16(csum))
}

func (pkt *ipPacket) calcIPPseudoHeaderChecksum() (csum uint32) {
	csum += (uint32(pkt.header[12]) + uint32(pkt.header[14])) << 8
	csum += uint32(pkt.header[13]) + uint32(pkt.header[15])
	csum += (uint32(pkt.header[16]) + uint32(pkt.header[18])) << 8
	csum += uint32(pkt.header[17]) + uint32(pkt.header[19])

	length := uint32(len(pkt.payload))
	csum += uint32(pkt.ipProto)
	csum += length & 0xffff
	csum += length >> 16

	return csum
}

type addr struct {
	ip   string
	port uint16
}

func (a addr) String() string {
	return fmt.Sprintf("%v:%d", a.ip, a.port)
}

type fourtuple struct {
	src addr
	dst addr
}

func (ft fourtuple) String() string {
	return fmt.Sprintf("%v -> %v", ft.src, ft.dst)
}
