package user

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
)

type EBPFProbeKTCP struct {
	EBPFProbe
}

//对象初始化
func (e *EBPFProbeKTCP) Init(ctx context.Context, logger *log.Logger) error {
	e.EBPFProbe.Init(ctx, logger)
	e.probeObjects = &TCPProbeObjects{}
	e.probeBytes = TCPProbeBytes
	e.EBPFProbe.SetChild(e)
	return nil
}

func (e *EBPFProbeKTCP) AttachProbe() error {
	kp, err := link.Kprobe("tcp_set_state", e.probeObjects.(*TCPProbeObjects).KprobeTCPSetState)
	if err != nil {
		return fmt.Errorf("opening Kprobe: %s", err)
	}
	e.reader = append(e.reader, kp)

	// initDecodeFun
	e.probeObjects.initDecodeFun()
	return nil
}

type TCPProbeObjects struct {
	TCPProbePrograms
	TCPProbeMaps
	EBPFProbeObject
}

func (t *TCPProbeObjects) initDecodeFun() {
	//eventMap 与解码函数映射
	t.eventFuncMap = make(map[*ebpf.Map]IEventStruct)
	t.eventFuncMap[t.TCPEvents] = &TCPEvent{}
	return
}

func (d *TCPProbeObjects) Close() error {
	return _ProbeClose(&d.TCPProbePrograms, &d.TCPProbeMaps)
}

func (d *TCPProbeObjects) Events() []*ebpf.Map {
	//只需要读取UDPEvents
	var m = []*ebpf.Map{d.TCPEvents}
	return m
}

type TCPProbePrograms struct {
	KprobeTCPSetState *ebpf.Program `ebpf:"kprobe__tcp_set_state"`
}

func (p *TCPProbePrograms) Close() error {
	return _ProbeClose(
		p.KprobeTCPSetState,
	)
}

//
type TCPProbeMaps struct {
	TCPEvents *ebpf.Map `ebpf:"events"`
	Conns     *ebpf.Map `ebpf:"conns"`
}

func (m *TCPProbeMaps) Close() error {
	return _ProbeClose(
		m.TCPEvents,
		m.Conns,
	)
}

//go:embed bytecode/tcp_set_state_kern.o
var TCPProbeBytes []byte

func init() {
	Register(&EBPFProbeKTCP{EBPFProbe{name: "EBPFProbeKTCP", probeType: PROBE_TYPE_KPROBE}})
}
