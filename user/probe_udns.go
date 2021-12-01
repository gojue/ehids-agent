package user

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"log"
)

type EBPFProbeUDNS struct {
	EBPFProbe
}

//对象初始化
func (e *EBPFProbeUDNS) Init(ctx context.Context, logger *log.Logger) error {
	e.EBPFProbe.Init(ctx, logger)
	e.probeObjects = &DNSProbeObjects{}
	e.probeBytes = DNSProbeBytes
	e.EBPFProbe.SetChild(e)
	return nil
}

func (e *EBPFProbeUDNS) AttachProbe() error {
	ex, err := link.OpenExecutable("/lib/x86_64-linux-gnu/libc.so.6")
	if err != nil {
		return fmt.Errorf("cant open executable /lib/x86_64-linux-gnu/libc.so.6 :%v", err)
	}
	kp, err := ex.Uprobe("getaddrinfo", e.probeObjects.(*DNSProbeObjects).KprobeDNSGet, nil)
	if err != nil {
		return fmt.Errorf("opening uprobe: %s", err)
	}
	e.reader = append(e.reader, kp)

	kpr, err := ex.Uretprobe("getaddrinfo", e.probeObjects.(*DNSProbeObjects).KprobeDNSGetRet, nil)
	if err != nil {
		return fmt.Errorf("opening kprobe: %s", err)
	}
	e.reader = append(e.reader, kpr)

	// initDecodeFun
	e.probeObjects.initDecodeFun()
	return nil
}

type DNSProbeObjects struct {
	DNSProbePrograms
	DNSProbeMaps
	EBPFProbeObject
}

func (t *DNSProbeObjects) initDecodeFun() {
	//eventMap 与解码函数映射
	t.eventFuncMap = make(map[*ebpf.Map]IEventStruct)
	t.eventFuncMap[t.DNSEvents] = &DNSEVENT{}
	return
}

func (d *DNSProbeObjects) Close() error {
	err := d.DNSProbePrograms.Close()
	if err != nil {
		return err
	}
	return d.DNSProbeMaps.Close()
}

func (d *DNSProbeObjects) Events() []*ebpf.Map {
	var m = []*ebpf.Map{d.DNSEvents}
	return m
}

type DNSProbePrograms struct {
	KprobeDNSGet    *ebpf.Program `ebpf:"getaddrinfo_entry"`
	KprobeDNSGetRet *ebpf.Program `ebpf:"getaddrinfo_return"`
}

func (p *DNSProbePrograms) Close() error {
	e := p.KprobeDNSGet.Close()
	if e != nil {
		return e
	}
	return p.KprobeDNSGetRet.Close()
}

//
type DNSProbeMaps struct {
	DNSEvents *ebpf.Map `ebpf:"events"`
}

func (m *DNSProbeMaps) Close() error {
	return m.DNSEvents.Close()
}

//go:embed bytecode/dns_lookup_kern.o
var DNSProbeBytes []byte

func init() {
	Register(&EBPFProbeUDNS{EBPFProbe{name: "EBPFProbeUDNS", probeType: PROBE_TYPE_UPROBE}})
}
