package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
)

type Question struct {
	QName  string
	QType  uint16
	QClass uint16
}

func ParseQuestion(reader *bytes.Reader) (*Question, error) {

	question := new(Question)

	binary.Read(reader, binary.LittleEndian, question.QType)
	binary.Read(reader, binary.LittleEndian, question.QClass)

	return nil, nil
}

func ExtractName(reader bytes.Reader) {

}

func parseDNSQuestion(data []byte, offset int) (*Question, int, error) {
	qname, newOffset, err := parseQName(data, offset)
	if err != nil {
		return nil, newOffset, err
	}

	if newOffset+4 > len(data) {
		return nil, newOffset, fmt.Errorf("incomplete DNS question")
	}

	qtype := binary.BigEndian.Uint16(data[newOffset : newOffset+2])
	qclass := binary.BigEndian.Uint16(data[newOffset+2 : newOffset+4])

	question := &Question{
		QName:  qname,
		QType:  qtype,
		QClass: qclass,
	}

	return question, newOffset + 4, nil
}

func parseQName(data []byte, offset int) (string, int, error) {
	var labels []string
	i := offset
	for {
		if i >= len(data) {
			return "", i, fmt.Errorf("offset beyond data length")
		}
		length := int(data[i])
		if length == 0 {
			i++
			break
		}

		if length&0xC0 == 0xC0 {
			if i+1 >= len(data) {
				return "", i, fmt.Errorf("pointer offset beyond data length")
			}
			pointerOffset := int(binary.BigEndian.Uint16(data[i:i+2]) & 0x3FFF)
			if pointerOffset >= len(data) {
				return "", i, fmt.Errorf("pointer offset out of bounds")
			}

			pointedName, _, err := parseQName(data, pointerOffset)
			if err != nil {
				return "", i, err
			}
			labels = append(labels, pointedName)
			i += 2
			break
		} else {
			i++
			labels = append(labels, string(data[i:i+length]))
			i += length
		}
	}

	return strings.Join(labels, "."), i, nil
}

func parseDNSResponse(data []byte, cache *DNSCache) error {
	header, err := parseDNSHeader(data)
	if err != nil {
		return fmt.Errorf("failed to parse DNS header: %v", err)
	}

	offset := 12 

	for i := 0; i < int(header.QdCount); i++ {
		_, newOffset, err := parseQName(data, offset)
		if err != nil {
			return fmt.Errorf("failed to parse question: %v", err)
		}
		offset = newOffset + 4 
	}

	for i := 0; i < int(header.AnCount); i++ {
		domain, newOffset, err := parseQName(data, offset)
		if err != nil {
			return fmt.Errorf("failed to parse answer: %v", err)
		}
		offset = newOffset

		if offset+10 > len(data) {
			return fmt.Errorf("answer section is too short")
		}

		atype := binary.BigEndian.Uint16(data[offset : offset+2])
		aclass := binary.BigEndian.Uint16(data[offset+2 : offset+4])
		ttl := binary.BigEndian.Uint32(data[offset+4 : offset+8])
		dataLen := binary.BigEndian.Uint16(data[offset+8 : offset+10])
		offset += 10

		if atype == 1 && aclass == 1 && dataLen == 4 { 
			ip := net.IPv4(data[offset], data[offset+1], data[offset+2], data[offset+3])
			cache.cacheARecord(domain, ip, ttl)
			log.Printf("Cached A record for %s: %s (TTL: %d seconds)", domain, ip.String(), ttl)
		}

		offset += int(dataLen)
	}

	return nil
}
