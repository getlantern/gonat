package gonat

import (
	"encoding/hex"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/assert"
)

func TestTCP(t *testing.T) {
	raw, err := hex.DecodeString("45000088dc9340004006e6c0c0a801e650f96394a8cc0050eeba8cabdde4fcaa801800e5779600000101080a5f691ad1a5fab79d474554202f3147422e7a697020485454502f312e310d0a486f73743a2038302e3234392e39392e3134380d0a557365722d4167656e743a206375726c2f372e35382e300d0a4163636570743a202a2f2a0d0a0d0a")
	if !assert.NoError(t, err) {
		return
	}

	pkt, err := parseIPPacket(raw)
	if !assert.NoError(t, err) {
		return
	}

	assert.Equal(t, "192.168.1.230:43212", pkt.ft().src.String())
	assert.Equal(t, "80.249.99.148:80", pkt.ft().dst.String())

	pkt.recalcIPChecksum()
	pkt.recalcTCPChecksum()
	expectedIPChecksum, expectedTCPChecksum := checksumsViaGoPacket(raw)
	assert.Equal(t, expectedIPChecksum, pkt.ipChecksum())
	assert.Equal(t, expectedTCPChecksum, pkt.tcpChecksum())
}

// for some reason, the TCP checksum in the test data doesn't match what's calculated by RFC 793,
// so we round-trip through gopacket to calculate the expected TCP checksum
func checksumsViaGoPacket(data []byte) (uint16, uint16) {
	packet, ip, tcp := gopacketLayers(data)
	if ip == nil || tcp == nil {
		return 0, 0
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	err := gopacket.SerializePacket(buf, opts, packet)
	if err != nil {
		log.Error(err)
		return 0, 0
	}
	_, ip, tcp = gopacketLayers(buf.Bytes())
	if ip == nil || tcp == nil {
		return 0, 0
	}
	return ip.Checksum, tcp.Checksum
}

func gopacketLayers(data []byte) (gopacket.Packet, *layers.IPv4, *layers.TCP) {
	packet := gopacket.NewPacket(data, layers.LayerTypeIPv4, gopacket.Default)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			return packet, ip, tcp
		}
	}

	return nil, nil, nil
}
