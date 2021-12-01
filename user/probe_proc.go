package user

import (
	"context"
	_ "embed"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type EBPFProbeProc struct {
	EBPFProbe
}

//对象初始化
func (e *EBPFProbeProc) Init(ctx context.Context, logger *log.Logger) error {
	e.EBPFProbe.Init(ctx, logger)
	e.probeObjects = &ProcProbeObjects{}
	e.probeBytes = ProcProbeBytes
	e.EBPFProbe.SetChild(e)
	return nil
}

func (e *EBPFProbeProc) AttachProbe() error {

	tp1, err := link.Kretprobe("copy_process", e.probeObjects.(*ProcProbeObjects).KretprobeCopyProcess) // fork
	if err != nil {
		log.Fatalf("link func: %s", err)
	}
	e.reader = append(e.reader, tp1)

	// initDecodeFun
	e.probeObjects.initDecodeFun()
	return nil
}

type ProcProbeObjects struct {
	ProcProbePrograms
	ProcProbeMaps
	EBPFProbeObject
}

func (t *ProcProbeObjects) initDecodeFun() {
	//eventMap 与解码函数映射
	t.eventFuncMap = make(map[*ebpf.Map]IEventStruct)
	t.eventFuncMap[t.RingbufProc] = &ForkProcEvent{}
	return
}

func (d *ProcProbeObjects) Close() error {
	err := d.ProcProbePrograms.Close()
	if err != nil {
		return err
	}
	return d.ProcProbeMaps.Close()
}

func (d *ProcProbeObjects) Events() []*ebpf.Map {
	var m = []*ebpf.Map{d.RingbufProc}
	return m
}

type ProcProbePrograms struct {
	KretprobeCopyProcess *ebpf.Program `ebpf:"kretprobe_copy_process"`
}

func (p *ProcProbePrograms) Close() (e error) {
	e = p.KretprobeCopyProcess.Close()
	if e != nil {
		return e
	}
	return
}

//
type ProcProbeMaps struct {
	RingbufProc *ebpf.Map `ebpf:"ringbuf_proc"`
}

func (m *ProcProbeMaps) Close() error {
	return m.RingbufProc.Close()
}

//go:embed bytecode/proc_kern.o
var ProcProbeBytes []byte

func init() {
	Register(&EBPFProbeProc{EBPFProbe{name: "EBPFProbeProc", probeType: PROBE_TYPE_KPROBE}})
}
