package dns

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var upstreamAddress string = "8.8.8.8:53"

var (
	requestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "dns_request_duration_seconds",
			Help:    "Histogram of response latency for DNS requests.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"status"}, // Label for success or failure
	)
)

func RequestDurationMetrics() {
	prometheus.MustRegister(requestDuration)
}

func queryUpstreamDNS(query []byte) ([]byte, error) {
	conn, err := net.Dial("udp", upstreamAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to upstream DNS server: %v", err)
	}
	defer conn.Close()

	_, err = conn.Write(query)
	if err != nil {
		return nil, fmt.Errorf("failed to send query to upstream DNS server: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))

	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil {
		return nil, fmt.Errorf("failed to read response from upstream DNS server: %v", err)
	}

	return response[:n], nil
}

func HandleDNSQuery(conn *net.UDPConn, clientAddr *net.UDPAddr, buffer []byte, dnsCache *DNSCache) {

	startTime := time.Now()

	header, err := parseDNSHeader(buffer)
	if err != nil {
		log.Printf("Failed to parse DNS header: %v", err)
		return
	}

	if header.QdCount > 0 {
		question, _, err := parseDNSQuestion(buffer, 12)
		if err != nil {
			log.Printf("Failed to parse DNS question: %v", err)
			return
		}

		log.Printf("DNS Question: %+v\n", question)

		cachedIP, found := dnsCache.getARecord(question.QName)
		if found {
			log.Printf("Cache hit for %s: %s", question.QName, cachedIP.String())
			response := buildDNSResponse(buffer, cachedIP)
			_, err = conn.WriteToUDP(response, clientAddr)
			if err != nil {
				log.Printf("Failed to send cached DNS response: %v", err)
			}
		} else {
			upstreamResponse, err := queryUpstreamDNS(buffer)
			if err != nil {
				log.Printf("Failed to query upstream DNS server: %v", err)
				return
			}

			err = parseDNSResponse(upstreamResponse, dnsCache)
			if err != nil {
				log.Printf("Failed to parse upstream DNS response: %v", err)
				return
			}

			_, err = conn.WriteToUDP(upstreamResponse, clientAddr)
			if err != nil {
				log.Printf("Failed to send upstream DNS response: %v", err)
			}
		}
	}

	requestDuration.WithLabelValues("success").Observe(float64(time.Since(startTime).Seconds()))
}
func buildDNSResponse(query []byte, ip net.IP) []byte {
	response := make([]byte, 512)
	copy(response, query)

	response[2] = 0x81
	response[3] = 0x80

	binary.BigEndian.PutUint16(response[6:8], 1)

	offset := len(query)

	copy(response[offset:], query[12:offset])

	offset += len(query) - 12

	binary.BigEndian.PutUint16(response[offset:], 0xc00c)
	offset += 2

	binary.BigEndian.PutUint16(response[offset:], 1)
	offset += 2

	binary.BigEndian.PutUint16(response[offset:], 1)
	offset += 2

	binary.BigEndian.PutUint32(response[offset:], 300)
	offset += 4

	binary.BigEndian.PutUint16(response[offset:], 4)
	offset += 2

	copy(response[offset:], ip.To4())
	offset += 4

	return response[:offset]
}
