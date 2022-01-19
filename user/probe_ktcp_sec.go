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

type MTCPSecProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

//对象初始化
func (this *MTCPSecProbe) Init(ctx context.Context, logger *log.Logger) error {
	this.Module.Init(ctx, logger)
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (this *MTCPSecProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MTCPSecProbe) start() error {

	// fetch ebpf assets
	javaBuf, err := assets.Asset("user/bytecode/sec_socket_connect_kern.o")
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

func (this *MTCPSecProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

func (this *MTCPSecProbe) setupManagers() {
	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "kprobe/security_socket_connect",
				EbpfFuncName:     "kprobe__security_socket_connect",
				AttachToFuncName: "security_socket_connect",
			},
		},
		//Ipv4Events  *ebpf.Map `ebpf:"ipv4_events"`
		//Ipv6Events  *ebpf.Map `ebpf:"ipv6_events"`
		//OtherEvents *ebpf.Map `ebpf:"other_socket_events"`
		Maps: []*manager.Map{
			{
				Name: "ipv4_events",
			},
			{
				Name: "ipv6_events",
			},
			{
				Name: "other_socket_events",
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

func (this *MTCPSecProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MTCPSecProbe) initDecodeFun() error {
	//eventMap 与解码函数映射
	IPv4EventsMap, found, err := this.bpfManager.GetMap("ipv4_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	this.eventMaps = append(this.eventMaps, IPv4EventsMap)
	this.eventFuncMaps[IPv4EventsMap] = &EventIPV4{}

	IPv6EventsMap, found, err := this.bpfManager.GetMap("ipv6_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	this.eventMaps = append(this.eventMaps, IPv6EventsMap)
	this.eventFuncMaps[IPv6EventsMap] = &EventIPV6{}

	otherEventsMap, found, err := this.bpfManager.GetMap("other_socket_events")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	this.eventMaps = append(this.eventMaps, otherEventsMap)
	this.eventFuncMaps[otherEventsMap] = &EventOther{}
	return nil
}

func (this *MTCPSecProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MTCPSecProbe{}
	mod.name = "EBPFProbeKTCPSec"
	mod.mType = PROBE_TYPE_KPROBE
	Register(mod)
}
