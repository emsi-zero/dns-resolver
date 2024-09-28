package main

import (
	"dns-resolver/internal/dns"
	"log"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	dnsRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_requests_total",
			Help: "Total number of DNS requests received.",
		},
		[]string{"status"}, // Label for success or failure
	)
)

func main() {

	prometheus.MustRegister(dnsRequests)
	dns.RequestDurationMetrics()
	dns.RegisterCacheMetrics()

	http.Handle("/metrics", promhttp.Handler())
	go func() {
		log.Fatal(http.ListenAndServe(":2112", nil))
	}()

	dnsCache := dns.NewDNSCache()

	addr := net.UDPAddr{
		Port: 5300,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("Failed to set up UDP listener: %v", err)
	}
	defer conn.Close()

	log.Printf("DNS server started on %s\n", addr.String())

	buffer := make([]byte, 512)
	for {
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("Error receiving UDP packet: %v", err)
			dnsRequests.WithLabelValues("failed").Inc()
			continue
		}

		dnsRequests.WithLabelValues("received").Inc()
		// Spawn a new goroutine to handle the DNS query concurrently
		go dns.HandleDNSQuery(conn, clientAddr, buffer[:n], dnsCache)
	}
}
