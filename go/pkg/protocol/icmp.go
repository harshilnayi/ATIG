package protocol

import (
	"encoding/binary"
)

type ICMPType uint8
type ICMPCode uint8

type ICMPHeader struct {
	Type     ICMPType
	Code     ICMPCode
	Checksum uint16
	Body     []byte
}

const (
	ICMPv4EchoReply ICMPType = 0
	ICMPv4Echo      ICMPType = 8
	ICMPv4TimeExceeded ICMPType = 11
)

func ParseICMPHeader(data []byte) (*ICMPHeader, error) {
	if len(data) < 8 {
		return nil, ErrInvalidHeader
	}

	return &ICMPHeader{
		Type:     ICMPType(data[0]),
		Code:     ICMPCode(data[1]),
		Checksum: binary.BigEndian.Uint16(data[2:4]),
		Body:     data[4:],
	}, nil
}

func (i *ICMPHeader) String() string {
	switch i.Type {
	case ICMPv4Echo:
		return "Echo Request"
	case ICMPv4EchoReply:
		return "Echo Reply"
	case ICMPv4TimeExceeded:
		return "Time Exceeded"
	default:
		return "Unknown"
	}
}
