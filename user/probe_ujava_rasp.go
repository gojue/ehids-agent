package user

import (
	"context"
	_ "embed"
	"fmt"
	"log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type EBPFProbeUJAVA struct {
	EBPFProbe
}

//对象初始化
func (e *EBPFProbeUJAVA) Init(ctx context.Context, logger *log.Logger) error {
	e.EBPFProbe.Init(ctx, logger)
	e.probeObjects = &JAVAProbeObjects{}
	e.probeBytes = JAVAProbeBytes
	e.EBPFProbe.SetChild(e)
	return nil
}

func (e *EBPFProbeUJAVA) AttachProbe() error {
	/*
		openjdk version "1.8.0_292"
		OpenJDK Runtime Environment (build 1.8.0_292-8u292-b10-0ubuntu1-b10)
		OpenJDK 64-Bit Server VM (build 25.292-b10, mixed mode)
	*/
	ex, err := link.OpenExecutable("/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/libjava.so")
	if err != nil {
		return fmt.Errorf("cant open executable /usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/libjava.so:%v", err)
	}

	// sub_19C30  == JDK_execvpe(p->mode, p->argv[0], p->argv, p->envv);
	// 		md5sum : 38590d0382d776234201996e99487110  /usr/lib/jvm/java-8-openjdk-amd64/jre/lib/amd64/libjava.so

	kp, err := ex.Uprobe("", e.probeObjects.(*JAVAProbeObjects).UprobeJavaEP, &link.UprobeOptions{Offset: 0x19C30})
	if err != nil {
		return fmt.Errorf("opening uprobe: %s", err)
	}
	e.reader = append(e.reader, kp)

	// initDecodeFun
	e.probeObjects.initDecodeFun()
	return nil
}

type JAVAProbeObjects struct {
	JAVAProbePrograms
	JAVAProbeMaps
	EBPFProbeObject
}

func (t *JAVAProbeObjects) initDecodeFun() {
	//eventMap 与解码函数映射
	t.eventFuncMap = make(map[*ebpf.Map]IEventStruct)
	t.eventFuncMap[t.JavaJDKExecvpeEvents] = &JavaJDKExecPeEvent{}
	return
}

func (d *JAVAProbeObjects) Close() error {
	err := d.JAVAProbePrograms.Close()
	if err != nil {
		return err
	}
	return d.JAVAProbeMaps.Close()
}

func (d *JAVAProbeObjects) Events() []*ebpf.Map {
	var m = []*ebpf.Map{d.JavaJDKExecvpeEvents}
	return m
}

type JAVAProbePrograms struct {
	UprobeJavaEP *ebpf.Program `ebpf:"java_JDK_execvpe"`
}

func (p *JAVAProbePrograms) Close() error {
	e := p.UprobeJavaEP.Close()
	if e != nil {
		return e
	}
	return nil
}

//
type JAVAProbeMaps struct {
	JavaJDKExecvpeEvents *ebpf.Map `ebpf:"jdk_execvpe_events"`
}

func (m *JAVAProbeMaps) Close() error {
	return m.JavaJDKExecvpeEvents.Close()
}

//go:embed bytecode/java_exec_kern.o
var JAVAProbeBytes []byte

func init() {
	Register(&EBPFProbeUJAVA{EBPFProbe{name: "EBPFProbeUJavaRASP", probeType: PROBE_TYPE_UPROBE}})
}
