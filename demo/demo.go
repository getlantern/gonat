package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"

	"github.com/getlantern/golog"
	"github.com/getlantern/gonat"
	tun "github.com/getlantern/gotun"
)

var (
	log = golog.LoggerFor("gotun-demo")
)

var (
	tunDevice = flag.String("tun-device", "tun0", "tun device name")
	tunAddr   = flag.String("tun-address", "10.0.0.2", "tun device address")
	tunMask   = flag.String("tun-mask", "255.255.255.0", "tun device netmask")
	tunGW     = flag.String("tun-gw", "10.0.0.1", "tun device gateway")
	ifOut     = flag.String("ifout", "en0", "name of interface to use for outbound connections")
	tcpDest   = flag.String("tcpdest", "speedtest-ny.turnkeyinternet.net", "destination to which to connect all TCP traffic")
	udpDest   = flag.String("udpdest", "8.8.8.8", "destination to which to connect all UDP traffic")
	pprofAddr = flag.String("pprofaddr", "", "pprof address to listen on, not activate pprof if empty")
)

type fivetuple struct {
	proto            string
	srcIP, dstIP     string
	srcPort, dstPort int
}

func (ft fivetuple) String() string {
	return fmt.Sprintf("[%v] %v:%v -> %v:%v", ft.proto, ft.srcIP, ft.srcPort, ft.dstIP, ft.dstPort)
}

func main() {
	flag.Parse()

	if *pprofAddr != "" {
		go func() {
			log.Debugf("Starting pprof page at http://%s/debug/pprof", *pprofAddr)
			srv := &http.Server{
				Addr: *pprofAddr,
			}
			if err := srv.ListenAndServe(); err != nil {
				log.Error(err)
			}
		}()
	}

	dev, err := tun.OpenTunDevice(*tunDevice, *tunAddr, *tunGW, *tunMask)
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		<-ch
		log.Debug("Closing TUN device")
		dev.Close()
		log.Debug("Closed TUN device")
	}()

	s, err := gonat.NewServer(dev, &gonat.Opts{
		IFName: *ifOut,
		OnOutbound: func(pkt *gonat.IPPacket, ft gonat.FourTuple, boundPort uint16) {
			pkt.SetDest("80.249.99.148", 80)
		},
		OnInbound: func(pkt *gonat.IPPacket, ft gonat.FourTuple, boundPort uint16) {
			pkt.SetDest(ft.Src.IP, ft.Src.Port)
			pkt.SetSource("10.0.0.1", ft.Dst.Port)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	log.Debugf("Final result: %v", s.Serve())
}
