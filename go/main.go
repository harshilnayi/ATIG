package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/harshilnayi/atig/go/internal/pipeline"
	"github.com/harshilnayi/atig/go/pkg/packet"
)

func main() {
	log.Println("ATIG Go Engine starting...")

	cfg := packet.CaptureConfig{
		Interface: getEnv("CAPTURE_INTERFACE", ""),
		SnapLen:   65535,
		Active:    true,
	}

	capture := packet.NewCaptureEngine(cfg)
	if err := capture.Start(); err != nil {
		log.Fatalf("failed to start capture: %v", err)
	}
	defer capture.Stop()

	pipeline := pipeline.NewPipeline(capture)

	pipeline.AddStage(func(pkt gopacket.Packet) interface{} {
		if pkt == nil {
			return nil
		}

		ipLayer := pkt.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			ipLayer = pkt.Layer(layers.LayerTypeIPv6)
		}
		if ipLayer == nil {
			return nil
		}

		transport := pkt.Layer(layers.LayerTypeTCP)
		if transport == nil {
			transport = pkt.Layer(layers.LayerTypeUDP)
		}
		if transport == nil {
			return nil
		}

		return map[string]interface{}{
			"payload": pkt.ApplicationLayer(),
		}
	})

	pipeline.Start()

	go func() {
		for range pipeline.Output() {
		}
	}()

	log.Println("engine running, pressing Ctrl+C to stop")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("shutting down...")
	pipeline.Stop()
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
