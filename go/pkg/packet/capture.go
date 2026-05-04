package packet

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type CaptureConfig struct {
	Interface string
	SnapLen   int32
	Active    bool
}

type Packet struct {
	Data      []byte
	Timestamp time.Time
	Interface string
}

type CaptureEngine struct {
	config    CaptureConfig
	handle    *pcap.Handle
	packetSrc chan gopacket.Packet
	stopChan  chan struct{}
}

func NewCaptureEngine(cfg CaptureConfig) *CaptureEngine {
	return &CaptureEngine{
		config:   cfg,
		stopChan: make(chan struct{}),
	}
}

func (c *CaptureEngine) Start() error {
	if c.config.Interface == "" {
		iface, err := c.findDefaultInterface()
		if err != nil {
			return fmt.Errorf("no interface specified and couldn't find default: %w", err)
		}
		c.config.Interface = iface.Name
		log.Printf("using default interface: %s", iface.Name)
	}

	handle, err := pcap.OpenLive(c.config.Interface, c.config.SnapLen, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %w", c.config.Interface, err)
	}
	c.handle = handle

	filter := "tcp or udp or icmp"
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return fmt.Errorf("invalid BPF filter: %w", err)
	}

	c.packetSrc = make(chan gopacket.Packet, 1000)
	go c.captureLoop()

	log.Printf("capture started on %s with filter: %s", c.config.Interface, filter)
	return nil
}

func (c *CaptureEngine) captureLoop() {
	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())

	for {
		select {
		case <-c.stopChan:
			return
		default:
			packet, err := packetSource.NextPacket()
			if err != nil {
				select {
				case <-c.stopChan:
					return
				default:
					continue
				}
			}
			c.packetSrc <- packet
		}
	}
}

func (c *CaptureEngine) PacketStream() <-chan gopacket.Packet {
	return c.packetSrc
}

func (c *CaptureEngine) Stop() {
	close(c.stopChan)
	if c.handle != nil {
		c.handle.Close()
	}
}

func (c *CaptureEngine) findDefaultInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		if len(addrs) > 0 {
			return &iface, nil
		}
	}

	if len(ifaces) > 0 {
		return &ifaces[0], nil
	}
	return nil, fmt.Errorf("no network interface found")
}
