package user

import (
	"bytes"
	"context"
	"ehids/assets"
	"github.com/cilium/ebpf"
	manager "github.com/ehids/ebpfmanager"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
	"log"
	"math"
)

type MUDPProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

//对象初始化
func (this *MUDPProbe) Init(ctx context.Context, logger *log.Logger) error {
	this.Module.Init(ctx, logger)
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (this *MUDPProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MUDPProbe) start() error {

	// fetch ebpf assets
	javaBuf, err := assets.Asset("user/bytecode/udp_lookup_kern.o")
	if err != nil {
		return errors.Wrap(err, "couldn't find asset")
	}

	// setup the managers
	this.setupManagers()

	// initialize the bootstrap manager
	if err := this.bpfManager.InitWithOptions(bytes.NewReader(javaBuf), this.bpfManagerOptions); err != nil {
		return errors.Wrap(err, "couldn't init manager")
	}

	// start the bootstrap manager
	if err := this.bpfManager.Start(); err != nil {
		return errors.Wrap(err, "couldn't start bootstrap manager")
	}

	// 加载map信息，map对应events decode表。
	err = this.initDecodeFun()
	if err != nil {
		return err
	}

	return nil
}

func (this *MUDPProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

func (this *MUDPProbe) setupManagers() {
	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "kprobe/udp_recvmsg",
				EbpfFuncName:     "trace_udp_recvmsg",
				AttachToFuncName: "udp_recvmsg",
			},
			{
				Section:          "kretprobe/udp_recvmsg",
				EbpfFuncName:     "trace_ret_udp_recvmsg",
				AttachToFuncName: "udp_recvmsg",
			},
		},

		Maps: []*manager.Map{
			{
				Name: "dns_events",
			},
		},
	}

	this.bpfManagerOptions = manager.Options{
		DefaultKProbeMaxActive: 512,

		VerifierOptions: ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: 2097152,
			},
		},

		RLimit: &unix.Rlimit{
			Cur: math.MaxUint64,
			Max: math.MaxUint64,
		},
	}
}

func (this *MUDPProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MUDPProbe) initDecodeFun() error {
	//eventMap 与解码函数映射
	DNSEventsMap, found, err := this.bpfManager.GetMap("dns_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	this.eventMaps = append(this.eventMaps, DNSEventsMap)
	this.eventFuncMaps[DNSEventsMap] = &UDPEvent{}

	return nil
}

func (this *MUDPProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MUDPProbe{}
	mod.name = "EBPFProbeKUDP"
	mod.mType = PROBE_TYPE_KPROBE
	Register(mod)
}
