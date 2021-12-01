package user

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
)

type EBPFProbeKTCPSec struct {
	EBPFProbe
}

//对象初始化
func (e *EBPFProbeKTCPSec) Init(ctx context.Context, logger *log.Logger) error {
	e.EBPFProbe.Init(ctx, logger)
	e.probeObjects = &TCPSecProbeObjects{}
	e.probeBytes = TCPSecProbeBytes
	e.EBPFProbe.SetChild(e)
	return nil
}

func (e *EBPFProbeKTCPSec) AttachProbe() error {
	kp, err := link.Kprobe("security_socket_connect", e.probeObjects.(*TCPSecProbeObjects).KprobeTCPSecSetState)
	if err != nil {
		return fmt.Errorf("opening Kprobe: %s", err)
	}
	e.reader = append(e.reader, kp)

	// initDecodeFun
	e.probeObjects.initDecodeFun()
	return nil
}

type TCPSecProbeObjects struct {
	TCPSecProbePrograms
	TCPSecProbeMaps
	EBPFProbeObject
}

func (t *TCPSecProbeObjects) initDecodeFun() {
	//eventMap 与解码函数映射
	t.eventFuncMap = make(map[*ebpf.Map]IEventStruct)
	t.eventFuncMap[t.Ipv4Events] = &EventIPV4{}
	t.eventFuncMap[t.Ipv6Events] = &EventIPV6{}
	t.eventFuncMap[t.OtherEvents] = &EventOther{}
	return
}

func (t *TCPSecProbeObjects) Close() error {
	return _ProbeClose(&t.TCPSecProbePrograms, &t.TCPSecProbeMaps)
}

// Events 返回需要读取的event
func (t *TCPSecProbeObjects) Events() []*ebpf.Map {
	//只需要读取UDPEvents
	var m = []*ebpf.Map{t.Ipv4Events, t.Ipv6Events, t.OtherEvents}
	return m
}

type TCPSecProbePrograms struct {
	KprobeTCPSecSetState *ebpf.Program `ebpf:"kprobe__security_socket_connect"`
}

func (p *TCPSecProbePrograms) Close() error {
	return _ProbeClose(
		p.KprobeTCPSecSetState,
	)
}

//
type TCPSecProbeMaps struct {
	Ipv4Events  *ebpf.Map `ebpf:"ipv4_events"`
	Ipv6Events  *ebpf.Map `ebpf:"ipv6_events"`
	OtherEvents *ebpf.Map `ebpf:"other_socket_events"`
}

func (m *TCPSecProbeMaps) Close() error {
	return _ProbeClose(
		m.Ipv4Events,
		m.Ipv6Events,
		m.OtherEvents,
	)
}

//go:embed bytecode/sec_socket_connect_kern.o
var TCPSecProbeBytes []byte

func init() {
	Register(&EBPFProbeKTCPSec{EBPFProbe{name: "EBPFProbeKTCPSec", probeType: PROBE_TYPE_KPROBE}})
}
