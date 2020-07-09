package gonat

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/oxtoacart/bpool"
	"github.com/stretchr/testify/assert"
)

func TestTCP(t *testing.T) {
	raw, err := hex.DecodeString("45000088dc9340004006e6c0c0a801e650f96394a8cc0050eeba8cabdde4fcaa801800e5779600000101080a5f691ad1a5fab79d474554202f3147422e7a697020485454502f312e310d0a486f73743a2038302e3234392e39392e3134380d0a557365722d4167656e743a206375726c2f372e35382e300d0a4163636570743a202a2f2a0d0a0d0a")
	if !assert.NoError(t, err) {
		return
	}

	pkt, err := parseIPPacket(bpool.WrapByteSlice(raw, 0))
	if !assert.NoError(t, err, "Packet failed to parse") {
		return
	}

	assert.Equal(t, "192.168.1.230:43212", pkt.FT().Src.String())
	assert.Equal(t, "80.249.99.148:80", pkt.FT().Dst.String())

	pkt.recalcIPChecksum()
	pkt.recalcTCPChecksum()
	expectedIPChecksum, expectedTCPChecksum := checksumsViaGoPacket(raw, false)
	assert.Equal(t, expectedIPChecksum, pkt.ipChecksum())
	assert.Equal(t, expectedTCPChecksum, pkt.tcpChecksum())
}

func TestUDP(t *testing.T) {
	raw, err := hex.DecodeString("4500001f3d700000401100007f0000017f000005ee641f40000bfe2268690a")
	if !assert.NoError(t, err) {
		return
	}

	pkt, err := parseIPPacket(bpool.WrapByteSlice(raw, 0))
	if !assert.NoError(t, err, "Packet failed to parse") {
		return
	}

	assert.Equal(t, "127.0.0.1:61028", pkt.FT().Src.String())
	assert.Equal(t, "127.0.0.5:8000", pkt.FT().Dst.String())

	pkt.recalcIPChecksum()
	pkt.recalcUDPChecksum()
	expectedIPChecksum, expectedUDPChecksum := checksumsViaGoPacket(raw, true)
	assert.Equal(t, expectedIPChecksum, pkt.ipChecksum())
	assert.Equal(t, expectedUDPChecksum, pkt.udpChecksum())
}

func TestUDPTruncated(t *testing.T) {
	raw, err := hex.DecodeString("4500001f3d700000401100007f0000017f000005ee641f40000b")
	if assert.NoError(t, err) {
		return
	}

	_, err = parseIPPacket(bpool.WrapByteSlice(raw, 0))
	assert.Error(t, err, "UDP packet with truncated HDP header should fail to parse")
}

func TestHasRST(t *testing.T) {
	withRST, err := hex.DecodeString("450000280000400040063cce7f0000017f0000012710cc98000000003e4e28c15014000057160000")
	if !assert.NoError(t, err) {
		return
	}
	pkt, err := parseIPPacket(bpool.WrapByteSlice(withRST, 0))
	if !assert.NoError(t, err) {
		return
	}
	assert.True(t, pkt.HasTCPFlag(TCPFlagRST))

	withoutRST, err := hex.DecodeString(strings.Replace("45 00 00 48 4B 3E 40 00 40 06 DB 6F 0A 00 00 02 50 F9 63 94 CE AA 00 50 58 38 DD 0B 4A 59 0E F1 D0 10 60 00 3A EB 00 00 01 01 08 0A 98 0D 1B AA AF 42 43 CD 01 01 05 12 4A 5A FB 09 4A 5B 00 B1 4A 59 6F 19 4A 5A D9 19", " ", "", -1))
	if !assert.NoError(t, err) {
		return
	}
	pkt, err = parseIPPacket(bpool.WrapByteSlice(withoutRST, 0))
	if !assert.NoError(t, err) {
		return
	}
	assert.False(t, pkt.HasTCPFlag(TCPFlagRST))
}

// for some reason, the checksum in the test data doesn't match what's calculated by RFC 793,
// so we round-trip through gopacket to calculate the expected TCP checksum
func checksumsViaGoPacket(data []byte, protoUDP bool) (uint16, uint16) {
	packet, ip, tcp, udp := gopacketLayers(data)
	if ip == nil || (!protoUDP && tcp == nil) || (protoUDP && udp == nil) {
		return 0, 0
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}
	if protoUDP {
		udp.SetNetworkLayerForChecksum(ip)
	} else {
		tcp.SetNetworkLayerForChecksum(ip)
	}
	err := gopacket.SerializePacket(buf, opts, packet)
	if err != nil {
		log.Error(err)
		return 0, 0
	}
	_, ip, tcp, udp = gopacketLayers(buf.Bytes())
	if ip == nil || (!protoUDP && tcp == nil) || (protoUDP && udp == nil) {
		return 0, 0
	}

	if protoUDP {
		return ip.Checksum, udp.Checksum
	}
	return ip.Checksum, tcp.Checksum
}

func gopacketLayers(data []byte) (gopacket.Packet, *layers.IPv4, *layers.TCP, *layers.UDP) {
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			return packet, ip, tcp, nil
		}
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			return packet, ip, nil, udp
		}
	}

	return nil, nil, nil, nil
}
