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

type MProcProbe struct {
	Module
	bpfManager        *manager.Manager
	bpfManagerOptions manager.Options
	eventFuncMaps     map[*ebpf.Map]IEventStruct
	eventMaps         []*ebpf.Map
}

//对象初始化
func (this *MProcProbe) Init(ctx context.Context, logger *log.Logger) error {
	this.Module.Init(ctx, logger)
	this.Module.SetChild(this)
	this.eventMaps = make([]*ebpf.Map, 0, 2)
	this.eventFuncMaps = make(map[*ebpf.Map]IEventStruct)
	return nil
}

func (this *MProcProbe) Start() error {
	if err := this.start(); err != nil {
		return err
	}
	return nil
}

func (this *MProcProbe) start() error {

	// fetch ebpf assets
	javaBuf, err := assets.Asset("user/bytecode/proc_kern.o")
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

func (this *MProcProbe) Close() error {
	if err := this.bpfManager.Stop(manager.CleanAll); err != nil {
		return errors.Wrap(err, "couldn't stop manager")
	}
	return nil
}

func (this *MProcProbe) setupManagers() {
	this.bpfManager = &manager.Manager{
		Probes: []*manager.Probe{
			{
				Section:          "kretprobe/copy_process",
				EbpfFuncName:     "kretprobe_copy_process",
				AttachToFuncName: "copy_process",
			},
		},

		Maps: []*manager.Map{
			{
				Name: "ringbuf_proc",
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

func (this *MProcProbe) DecodeFun(em *ebpf.Map) (IEventStruct, bool) {
	fun, found := this.eventFuncMaps[em]
	return fun, found
}

func (this *MProcProbe) initDecodeFun() error {
	//eventMap 与解码函数映射
	procEventsMap, found, err := this.bpfManager.GetMap("ringbuf_proc")
	if err != nil {
		return err
	}
	if !found {
		return errors.New("cant found map:events")
	}
	this.eventMaps = append(this.eventMaps, procEventsMap)
	this.eventFuncMaps[procEventsMap] = &ForkProcEvent{}

	return nil
}

func (this *MProcProbe) Events() []*ebpf.Map {
	return this.eventMaps
}

func init() {
	mod := &MProcProbe{}
	mod.name = "EBPFProbeProc"
	mod.mType = PROBE_TYPE_KPROBE
	Register(mod)
}
