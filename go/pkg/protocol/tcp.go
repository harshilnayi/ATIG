package protocol

import (
	"encoding/binary"
	"net"
)

type TCPFlags struct {
	FIN, SYN, RST, PSH, ACK, URG bool
	ECN, CWR, ECE, NS            bool
}

type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8
	Flags      TCPFlags
	Window     uint16
	Checksum   uint16
	UrgentPtr  uint16
}

func ParseTCPHeader(data []byte) (*TCPHeader, error) {
	if len(data) < 20 {
		return nil, ErrInvalidHeader
	}

	header := &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		SeqNum:     binary.BigEndian.Uint32(data[4:8]),
		AckNum:     binary.BigEndian.Uint32(data[8:12]),
		DataOffset: data[12] >> 4,
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		UrgentPtr:  binary.BigEndian.Uint16(data[18:20]),
	}

	flagByte := data[13]
	header.Flags.FIN = (flagByte & 0x01) != 0
	header.Flags.SYN = (flagByte & 0x02) != 0
	header.Flags.RST = (flagByte & 0x04) != 0
	header.Flags.PSH = (flagByte & 0x08) != 0
	header.Flags.ACK = (flagByte & 0x10) != 0
	header.Flags.URG = (flagByte & 0x20) != 0
	header.Flags.ECE = (flagByte & 0x40) != 0
	header.Flags.CWR = (flagByte & 0x80) != 0

	return header, nil
}

func (t *TCPHeader) FlagsString() string {
	flags := ""
	if t.Flags.SYN && !t.Flags.ACK {
		flags = "SYN"
	} else if t.Flags.SYN && t.Flags.ACK {
		flags = "SYN-ACK"
	} else if t.Flags.FIN {
		flags = "FIN"
	} else if t.Flags.RST {
		flags = "RST"
	} else if t.Flags.ACK {
		flags = "ACK"
	}
	return flags
}

func IsValidTCPConnection(src, dst *TCPHeader) bool {
	return src.SYN && !src.ACK && dst.ACK && dst.SYN
}

func IsEstablished(header *TCPHeader) bool {
	return header.Flags.ACK
}

func IsConnectionTermination(header *TCPHeader) bool {
	return header.Flags.FIN || header.Flags.RST
}

var ErrInvalidHeader = &net.OpError{Op: "parse", Net: "tcp", Err: &net.DNSError{Err: "header too short", Name: "tcp"}}
