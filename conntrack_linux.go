package gonat

import (
	"net"
	"syscall"

	ct "github.com/ti-mo/conntrack"
)

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
