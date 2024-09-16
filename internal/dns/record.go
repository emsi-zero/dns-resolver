package dns

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	cacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_cache_hits_total",
			Help: "Total number of DNS cache hits.",
		},
		[]string{"status"}, // Label for cache hit or miss
	)
)

func RegisterCacheMetrics() {
	prometheus.MustRegister(cacheHits)
}

type DNSRecord struct {
	IPAddress  net.IP
	Expiration time.Time
}

type DNSCache struct {
	mu    sync.RWMutex
	cache map[string]*DNSRecord
}

func NewDNSCache() *DNSCache {
	return &DNSCache{
		cache: make(map[string]*DNSRecord),
	}
}

func (c *DNSCache) cacheARecord(domain string, ip net.IP, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()

	expiration := time.Now().Add(time.Duration(ttl) * time.Second)
	c.cache[domain] = &DNSRecord{
		IPAddress:  ip,
		Expiration: expiration,
	}

	log.Printf("Cached A record for %s: %s (TTL: %d seconds)", domain, ip.String(), ttl)
}

func (c *DNSCache) getARecord(domain string) (net.IP, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	record, found := c.cache[domain]
	if !found {
		cacheHits.WithLabelValues("miss").Inc()
		return nil, false
	} else {
		cacheHits.WithLabelValues("hit").Inc()
	}

	if time.Now().After(record.Expiration) {
		// Record has expired
		delete(c.cache, domain)
		return nil, false
	}

	return record.IPAddress, true
}
