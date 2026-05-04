package pipeline

import (
	"log"
	"sync"

	"github.com/google/gopacket"
	"github.com/harshilnayi/atig/go/pkg/packet"
)

type Stage func(gopacket.Packet) interface{}

type Pipeline struct {
	stages   []Stage
	input    chan gopacket.Packet
	output   chan interface{}
	wg       sync.WaitGroup
	running  bool
}

func NewPipeline(cap *packet.CaptureEngine) *Pipeline {
	return &Pipeline{
		stages: make([]Stage, 0),
		input:  cap.PacketStream(),
		output: make(chan interface{}, 1000),
	}
}

func (p *Pipeline) AddStage(stage Stage) *Pipeline {
	p.stages = append(p.stages, stage)
	return p
}

func (p *Pipeline) Start() {
	p.running = true

	for i, stage := range p.stages {
		p.wg.Add(1)
		go func(idx int, s Stage) {
			defer p.wg.Done()
			p.runStage(s)
		}(i, stage)
	}

	log.Printf("pipeline started with %d stages", len(p.stages))
}

func (p *Pipeline) runStage(stage Stage) {
	for pkt := range p.input {
		result := stage(pkt)
		if result != nil {
			p.output <- result
		}
	}
}

func (p *Pipeline) Output() <-chan interface{} {
	return p.output
}

func (p *Pipeline) Stop() {
	p.running = false
	close(p.input)
	p.wg.Wait()
	close(p.output)
	log.Println("pipeline stopped")
}
