package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type Header struct {
	ID      uint16
	Flags   uint16
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}

func parseDNSHeader(data []byte) (*Header, error) {
	if len(data) < 12 {
		return nil, fmt.Errorf("data too short to be a DNS packet")
	}

	header := &Header{
		ID:      binary.BigEndian.Uint16(data[0:2]),
		Flags:   binary.BigEndian.Uint16(data[2:4]),
		QdCount: binary.BigEndian.Uint16(data[4:6]),
		AnCount: binary.BigEndian.Uint16(data[6:8]),
		NsCount: binary.BigEndian.Uint16(data[8:10]),
		ArCount: binary.BigEndian.Uint16(data[10:12]),
	}

	return header, nil
}

func (h *Header) ToBytes() []byte {
	header := new(bytes.Buffer)

	binary.Write(header, binary.BigEndian, h.ID)
	binary.Write(header, binary.BigEndian, h.Flags)
	binary.Write(header, binary.BigEndian, h.QdCount)
	binary.Write(header, binary.BigEndian, h.AnCount)
	binary.Write(header, binary.BigEndian, h.NsCount)
	binary.Write(header, binary.BigEndian, h.ArCount)
	return header.Bytes()
}
