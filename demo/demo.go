package main

import (
	"flag"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

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
	mtu       = flag.Int("mtu", 1500, "maximum transmission unit for TUN device")
	ifOut     = flag.String("ifout", "", "name of interface to use for outbound connections")
	tcpDest   = flag.String("tcpdest", "80.249.99.148", "destination to which to connect all TCP traffic")
	udpDest   = flag.String("udpdest", "8.8.8.8", "destination to which to connect all UDP traffic")
	pprofAddr = flag.String("pprofaddr", "", "pprof address to listen on, not activate pprof if empty")
)

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

	dev, err := tun.OpenTunDevice(*tunDevice, *tunAddr, *tunGW, *tunMask, *mtu)
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()

	s, err := gonat.NewServer(dev, &gonat.Opts{
		IFName:      *ifOut,
		IdleTimeout: 5 * time.Second,
		BufferDepth: 10000,
		OnOutbound: func(pkt *gonat.IPPacket) {
			pkt.SetDest(*tcpDest, pkt.FT().Dst.Port)
		},
		OnInbound: func(pkt *gonat.IPPacket, ft gonat.FourTuple) {
			pkt.SetSource(*tunGW, ft.Dst.Port)
		},
	})
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()

	ch := make(chan os.Signal, 1)
	signal.Notify(ch,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)
	go func() {
		<-ch
		log.Debug("Closing gonat server")
		s.Close()
		log.Debug("Closing TUN device")
		dev.Close()
		log.Debug("Finished closing")
		os.Exit(0)
	}()

	log.Debugf("Final result: %v", s.Serve())
}
