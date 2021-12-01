package user

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"io"
	"log"
	"os"
)

type IBPFProbe interface {
	// Init 初始化
	Init(context.Context, *log.Logger) error

	// GetProbeBytes  获取当前加载器的probebytes
	GetProbeBytes() []byte

	// ProbeName 获取当前probe的名字
	ProbeName() string

	// ProbeObjects ProbeObjects设置
	ProbeObjects() IClose

	// LoadToKernel load bpf字节码到内核
	LoadToKernel() error

	// AttachProbe hook到对应probe
	AttachProbe() error

	// Run 事件监听感知
	Run() error

	// Reader
	Reader() []IClose

	//OutPut 输出上报
	//OutPut() bool

	// Decode 解码，输出或发送到消息队列等
	Decode(*ebpf.Map, []byte) (string ,error)

	// Close 关闭退出
	Close() error
}

type EBPFProbe struct {
	probeBytes   []byte
	opts         *ebpf.CollectionOptions
	probeObjects IEBPFProbeObject
	reader       []IClose
	ctx          context.Context
	child        IBPFProbe
	logger       *log.Logger

	// probe的名字
	name string

	// probe的类型，uprobe,kprobe等
	probeType string
}

func (e *EBPFProbe) Child() IBPFProbe {
	return e.child
}

func (e *EBPFProbe) SetChild(child IBPFProbe) {
	e.child = child
}

func (e *EBPFProbe) Reader() []IClose {
	return e.reader
}

func (e *EBPFProbe) GetProbeBytes() []byte {
	return e.probeBytes
}

//对象初始化
func (e *EBPFProbe) Init(ctx context.Context, logger *log.Logger) {
	e.ctx = ctx
	//e.eventChan = make(chan []byte, 1024)
	e.logger = logger
	return
}

func (e *EBPFProbe) ProbeName() string {
	return e.name
}

func (e *EBPFProbe) ProbeObjects() IClose {
	return e.probeObjects
}

func (e *EBPFProbe) LoadToKernel() error {
	reader := bytes.NewReader(e.probeBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return fmt.Errorf("can't load Probe: %w, eBPF bytes length:%d", err, len(e.probeBytes))
	}

	err = spec.LoadAndAssign(e.probeObjects, e.opts)
	if err != nil {
		return err
	}
	e.reader = append(e.reader, e.probeObjects)
	return nil
}

func (e *EBPFProbe) Close() error {
	for _, closer := range e.reader {
		if err := closer.Close(); err != nil {
			return err
		}
	}

	// close child's reader
	for _, closer := range e.child.Reader() {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (e *EBPFProbe) AttachProbe() error {
	if e.child == nil {
		panic("e.AttachProbe not implemented yet")
	}
	return e.child.AttachProbe()
}

func (e *EBPFProbe) readEvents() error {
	var errChan = make(chan error, 8)

	for _, event := range e.probeObjects.Events() {
		switch  {
		case event.Type() == ebpf.RingBuf:
			go e.ringbufEventReader(errChan, event)
		case event.Type() == ebpf.PerfEventArray:
			go e.perfEventReader(errChan, event)
		default:
			errChan <- fmt.Errorf("Not support mapType:%s , mapinfo:%s", event.Type().String(),event.String())
		}
	}

	for {
		select {
		case err := <-errChan:
			return err
		}
	}
}

func (e *EBPFProbe) perfEventReader(errChan chan error, em *ebpf.Map)  {
	rd, err := perf.NewReader(em, os.Getpagesize())
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(),err)
		return
	}
	defer rd.Close()
	for {
		//判断ctx是不是结束
		select {
		case _ = <-e.ctx.Done():
			log.Printf("readEvent recived close signal from context.Done.")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if perf.IsClosed(err) {
				return
			}
			errChan <- fmt.Errorf("reading from perf event reader: %s", err)
			return
		}

		if record.LostSamples != 0 {
			log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		var result string
		result, err = e.child.Decode(em, record.RawSample)
		if err != nil {
			log.Printf("e.child.decode error:%v", err)
			continue
		}

		// 上报数据
		e.Write(fmt.Sprintf("probeName:%s, probeTpye:%s, %s", e.name, e.probeType, result))
	}
}

func (e *EBPFProbe) ringbufEventReader(errChan chan error, em *ebpf.Map)  {
	rd, err := ringbuf.NewReader(em)
	if err != nil {
		errChan <- fmt.Errorf("creating %s reader dns: %s", em.String(),err)
		return
	}
	defer rd.Close()
	for {
		//判断ctx是不是结束
		select {
		case _ = <-e.ctx.Done():
			e.logger.Printf("readEvent recived close signal from context.Done.")
			return
		default:
		}

		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				e.logger.Println("Received signal, exiting..")
				return
			}
			errChan <- fmt.Errorf("reading from ringbuf reader: %s", err)
			return
		}



		var result string
		result, err = e.child.Decode(em, record.RawSample)
		if err != nil {
			log.Printf("e.child.decode error:%v", err)
			continue
		}

		// 上报数据
		e.Write(fmt.Sprintf("probeName:%s, probeTpye:%s, %s", e.name, e.probeType, result))
	}
}

func (e *EBPFProbe) Run() error {
	err := e.LoadToKernel()
	if err != nil {
		return err
	}

	err = e.AttachProbe()
	if err != nil {
		return err
	}

	err = e.readEvents()
	if err != nil {
		return err
	}
	return nil
}

// 写入数据，或者上传到远程数据库，写入到其他chan 等。
func (e *EBPFProbe) Write(s string) {
	//
	e.logger.Println(s)
}

func (e *EBPFProbe) Decode(em *ebpf.Map, b []byte) (result string, err error) {
	es, found := e.probeObjects.DecodeFun(em)
	if !found {
		err = fmt.Errorf("can't found decode function :%s, address:%p", em.String(), em)
		return
	}
	result, err = e.probeObjects.EventsDecode(b, es)
	if err != nil {
		return
	}
	return
}

func _ProbeClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}
