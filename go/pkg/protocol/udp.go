package protocol

import (
	"encoding/binary"
)

type UDPHeader struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

func ParseUDPHeader(data []byte) (*UDPHeader, error) {
	if len(data) < 8 {
		return nil, ErrInvalidHeader
	}

	return &UDPHeader{
		SrcPort:  binary.BigEndian.Uint16(data[0:2]),
		DstPort:  binary.BigEndian.Uint16(data[2:4]),
		Length:   binary.BigEndian.Uint16(data[4:6]),
		Checksum: binary.BigEndian.Uint16(data[6:8]),
	}, nil
}

const DNSPort = 53

func IsDNSQuery(header *UDPHeader) bool {
	return header.DstPort == DNSPort || header.SrcPort == DNSPort
}
