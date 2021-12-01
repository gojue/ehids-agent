package user

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
)

type EBPFProbeKUDP struct {
	EBPFProbe
}

//对象初始化
func (e *EBPFProbeKUDP) Init(ctx context.Context, logger *log.Logger) error {
	e.EBPFProbe.Init(ctx, logger)
	e.probeObjects = &UDPProbeObjects{}
	e.probeBytes = UDPProbeBytes
	e.EBPFProbe.SetChild(e)
	return nil
}

func (e *EBPFProbeKUDP) AttachProbe() error {
	kp, err := link.Kprobe("udp_recvmsg", e.probeObjects.(*UDPProbeObjects).KprobeUDPRecvmsg)
	if err != nil {
		return fmt.Errorf("opening Kprobe: %s", err)
	}
	e.reader = append(e.reader, kp)

	kpr, err := link.Kretprobe("udp_recvmsg", e.probeObjects.(*UDPProbeObjects).KretprobeUDPRecvmsg)
	if err != nil {
		return fmt.Errorf("opening kprobe: %s", err)
	}

	e.reader = append(e.reader, kpr)

	// initDecodeFun
	e.probeObjects.initDecodeFun()
	return nil
}

type UDPProbeObjects struct {
	UDPProbePrograms
	UDPProbeMaps
	EBPFProbeObject
}

func (t *UDPProbeObjects) initDecodeFun() {
	//eventMap 与解码函数映射
	t.eventFuncMap = make(map[*ebpf.Map]IEventStruct)
	t.eventFuncMap[t.UDPEvents] = &UDPEvent{}
	return
}

func (d *UDPProbeObjects) Close() error {
	return _ProbeClose(&d.UDPProbePrograms, &d.UDPProbeMaps)
}

func (d *UDPProbeObjects) Events() []*ebpf.Map {
	//只需要读取UDPEvents
	var m = []*ebpf.Map{d.UDPProbeMaps.UDPEvents}
	return m
}

type UDPProbePrograms struct {
	KprobeUDPRecvmsg    *ebpf.Program `ebpf:"trace_udp_recvmsg"`
	KretprobeUDPRecvmsg *ebpf.Program `ebpf:"trace_ret_udp_recvmsg"`
}

func (p *UDPProbePrograms) Close() error {
	return _ProbeClose(
		p.KretprobeUDPRecvmsg,
		p.KretprobeUDPRecvmsg,
	)
}

//
type UDPProbeMaps struct {
	UDPEvents    *ebpf.Map `ebpf:"dns_events"`
	UDPData      *ebpf.Map `ebpf:"dns_data"`
	TblUDPMsgHdr *ebpf.Map `ebpf:"tbl_udp_msg_hdr"`
}

func (m *UDPProbeMaps) Close() error {
	return _ProbeClose(
		m.UDPData,
		m.TblUDPMsgHdr,
		m.UDPEvents,
	)
}

//go:embed bytecode/udp_lookup_kern.o
var UDPProbeBytes []byte

func init() {
	Register(&EBPFProbeKUDP{EBPFProbe{name: "EBPFProbeKUDP", probeType: PROBE_TYPE_KPROBE}})
}
