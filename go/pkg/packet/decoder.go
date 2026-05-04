package packet

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ProtocolInfo struct {
	SrcIP   net.IP
	DstIP   net.IP
	SrcPort uint16
	DstPort uint16
	Protocol string
}

type PacketMetadata struct {
	ProtocolInfo
	Flags     map[string]bool
	Payload   []byte
	Tunneling bool
}

func ParsePacket(packet gopacket.Packet) (*PacketMetadata, error) {
	meta := &PacketMetadata{
		Flags: make(map[string]bool),
	}

	// Extract IP layer
	ipLayer := packet.Layer(gopacket.LayerTypeIPv4)
	if ipLayer == nil {
		ipLayer = packet.Layer(gopacket.LayerTypeIPv6)
	}

	if ipLayer != nil {
		var ip *layers.IPv4
		var ip6 *layers.IPv6

		switch l := ipLayer.(type) {
		case *layers.IPv4:
			ip = l
			meta.ProtocolInfo.SrcIP = l.SrcIP
			meta.ProtocolInfo.DstIP = l.DstIP
			meta.ProtocolInfo.Protocol = l.NetworkProtocol.String()
		case *layers.IPv6:
			ip6 = l
			meta.ProtocolInfo.SrcIP = l.SrcIP
			meta.ProtocolInfo.DstIP = l.DstIP
			meta.ProtocolInfo.Protocol = l.NextHeader.String()
		}

		// Check for fragmentation handling
		if ip != nil && ip.FragOffset > 0 {
			log.Printf("fragmented packet detected at offset %d", ip.FragOffset)
		}
	}

	// Extract transport layer
	transportLayer := packet.Layer(gopacket.LayerTypeTCP)
	if transportLayer != nil {
		tcp := transportLayer.(*layers.TCP)
		meta.ProtocolInfo.SrcPort = uint16(tcp.SrcPort)
		meta.ProtocolInfo.DstPort = uint16(tcp.DstPort)

		// Track TCP flags
		if tcp.SYN {
			meta.Flags["SYN"] = true
		}
		if tcp.ACK {
			meta.Flags["ACK"] = true
		}
		if tcp.FIN {
			meta.Flags["FIN"] = true
		}
		if tcp.RST {
			meta.Flags["RST"] = true
		}

		// Payload extraction
		if len(tcp.LayerPayload()) > 0 {
			meta.Payload = tcp.LayerPayload()
		}
		return meta, nil
	}

	transportLayer = packet.Layer(gopacket.LayerTypeUDP)
	if transportLayer != nil {
		udp := transportLayer.(*layers.UDP)
		meta.ProtocolInfo.SrcPort = uint16(udp.SrcPort)
		meta.ProtocolInfo.DstPort = uint16(udp.DstPort)
		meta.Payload = udp.LayerPayload()
		return meta, nil
	}

	transportLayer = packet.Layer(gopacket.LayerTypeICMPv4)
	if transportLayer != nil {
		icmp := transportLayer.(*layers.ICMPv4)
		meta.ProtocolInfo.Protocol = "ICMP"
		meta.Payload = icmp.LayerPayload()
		return meta, nil
	}

	return meta, fmt.Errorf("no supported transport layer found")
}

func DecodeDNS(packet *PacketMetadata) (map[string]interface{}, error) {
	if len(packet.Payload) == 0 {
		return nil, fmt.Errorf("no payload for DNS decode")
	}

	// Basic DNS parsing - will expand as needed
	dnsInfo := map[string]interface{}{
		"raw": packet.Payload,
	}

	var dns layers.DNS
	err := dns.DecodeFromBytes(packet.Payload, gopacket.Default)
	if err != nil {
		return dnsInfo, nil
	}

	if dns.Qr {
		dnsInfo["type"] = "response"
		if len(dns.Answers) > 0 {
			dnsInfo["answers"] = dns.Answers[0].String()
		}
	} else {
		dnsInfo["type"] = "query"
		if len(dns.Questions) > 0 {
			dnsInfo["question"] = string(dns.Questions[0].Name)
		}
	}

	return dnsInfo, nil
}

func DecodeHTTP(packet *PacketMetadata) (map[string]interface{}, error) {
	if len(packet.Payload) == 0 {
		return nil, fmt.Errorf("no payload for HTTP decode")
	}

	httpInfo := map[string]interface{}{
		"raw": packet.Payload,
	}

	return httpInfo, nil
}

type Decoder struct {
	Src chan *PacketMetadata
}

func NewDecoder() *Decoder {
	return &Decoder{
		Src: make(chan *PacketMetadata, 1000),
	}
}

func (d *Decoder) Process(packet gopacket.Packet) *PacketMetadata {
	meta, err := ParsePacket(packet)
	if err != nil {
		log.Printf("packet parse error: %v", err)
		return nil
	}

	// Check for interesting application layers
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		switch appLayer.LayerType() {
		case layers.LayerTypeDNS:
			if dnsInfo, err := DecodeDNS(meta); err == nil {
				meta.Payload = []byte(fmt.Sprintf("%v", dnsInfo))
			}
		case layers.LayerTypeHTTP:
			if httpInfo, err := DecodeHTTP(meta); err == nil {
				meta.Payload = []byte(fmt.Sprintf("%v", httpInfo))
			}
		}
	}

	return meta
}
