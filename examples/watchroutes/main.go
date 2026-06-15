// Command watchroutes embeds goisis as a library and reacts to route changes
// instead of programming the kernel FIB. This is the pattern for feeding an
// alternative dataplane — e.g. writing routes into eBPF maps — where goisis
// runs the IS-IS control plane and your code owns forwarding.
//
// Usage:
//
//	sudo watchroutes -interface eth0 -net 49.0001.0000.0000.0001.00
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/takehaya/goisis/pkg/datalink"
	"github.com/takehaya/goisis/pkg/fib"
	"github.com/takehaya/goisis/pkg/packet"
	"github.com/takehaya/goisis/pkg/server"
)

func main() {
	ifname := flag.String("interface", "", "interface to run IS-IS on")
	net := flag.String("net", "", "network entity title, e.g. 49.0001.0000.0000.0001.00")
	flag.Parse()
	if *ifname == "" || *net == "" {
		flag.Usage()
		os.Exit(2)
	}

	area, sysID, err := packet.ParseNET(*net)
	if err != nil {
		log.Fatal(err)
	}
	tr, err := datalink.OpenLinux(*ifname)
	if err != nil {
		log.Fatal(err)
	}

	// fib.Noop: goisis computes routes but does not touch the kernel; we
	// consume them via Subscribe and program our own dataplane instead.
	s, err := server.NewIsisServer(
		server.WithSystemID(sysID),
		server.WithAreaAddresses(area),
		server.WithCircuit(server.CircuitConfig{Name: *ifname, Transport: tr, Level1: true, Level2: true}),
		server.WithFIB(fib.Noop{}),
	)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		if err := s.Serve(ctx); err != nil {
			log.Printf("serve: %v", err)
		}
	}()

	sub, err := s.Subscribe(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer sub.Unsubscribe()

	log.Printf("watching IS-IS events on %s (%s)", *ifname, *net)
	for ev := range sub.Events {
		switch {
		case ev.Route != nil:
			// Replace this with your dataplane programming (e.g. an eBPF map).
			verb := "add"
			if ev.Withdrawn {
				verb = "withdraw"
			}
			log.Printf("route %s %s metric=%d nexthops=%v", verb, ev.Route.Prefix, ev.Route.Metric, ev.Route.NextHops)
		case ev.Adjacency != nil:
			log.Printf("adjacency %s %s %s", ev.Adjacency.SystemID, ev.Adjacency.Level, ev.Adjacency.State)
		}
	}
}
