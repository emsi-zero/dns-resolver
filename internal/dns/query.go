package dns

import (
	"bytes"
	"encoding/binary"
)

type Header struct {
	ID      uint16
	Flags   uint16
	QdCount uint16
	AnCount uint16
	NsCount uint16
	ArCount uint16
}

func ParseHeader(reader *bytes.Reader) {
	var header Header
	
	binary.Read(reader, binary.BigEndian, header.ID)
	binary.Read(reader, binary.BigEndian, header.Flags)
	binary.Read(reader, binary.BigEndian, header.QdCount)
	binary.Read(reader, binary.BigEndian, header.AnCount)
	binary.Read(reader, binary.BigEndian, header.NsCount)
	binary.Read(reader, binary.BigEndian, header.ArCount)
}

