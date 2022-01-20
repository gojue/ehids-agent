package user

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"
)

func GetEndian() binary.ByteOrder {
	var i int32 = 0x1
	v := (*[4]byte)(unsafe.Pointer(&i))
	if v[0] == 0 {
		return binary.BigEndian
	} else {
		return binary.LittleEndian
	}
}

var (
	ByteOrder = GetEndian()
)

type ProcEvent struct {
	Pid        uint32 `json:"pid"`
	Tgid       uint32 `json:"tgid"`
	NsPid      uint32 `json:"ns_pid"`
	NsTgid     uint32 `json:"ns_tgid"`
	PPid       uint32 `json:"ppid"`
	PTgid      uint32 `json:"ptgid"`
	NsPPid     uint32 `json:"ns_ppid"`
	NsPTgid    uint32 `json:"ns_ptgid"`
	PPPid      uint32 `json:"pppid"`
	PPTgid     uint32 `json:"pptgid"`
	NsPPPid    uint32 `json:"ns_pppid"`
	NsPPTgid   uint32 `json:"ns_pptgid"`
	Uid        uint32 `json:"uid"`
	Euid       uint32 `json:"euid"`
	Gid        uint32 `json:"gid"`
	Egid       uint32 `json:"egid"`
	UtsInum    uint32 `json:"uts_inum"`
	Start_time uint64 `json:"start_time"`
	Comm       string `json:"processname"`
	Cmdline    string `json:"command"`
	UtsName    string `json:"hostname"`
}

type BpfCallEvent struct {
	Type string `json:"bpf_cmd"`
	ProcEvent
}

func (this *BpfCallEvent) Decode(data []byte) error {
	cmd := BPFCmd(ByteOrder.Uint32(data[0:4]))
	this.Type = cmd.String()
	this.Pid = uint32(ByteOrder.Uint32(data[8:12]))
	this.Tgid = uint32(ByteOrder.Uint32(data[12:16]))
	this.NsPid = uint32(ByteOrder.Uint32(data[16:20]))
	this.NsTgid = uint32(ByteOrder.Uint32(data[20:24]))
	this.PPid = uint32(ByteOrder.Uint32(data[24:28]))
	this.PTgid = uint32(ByteOrder.Uint32(data[28:32]))
	this.NsPPid = uint32(ByteOrder.Uint32(data[32:36]))
	this.NsPTgid = uint32(ByteOrder.Uint32(data[36:40]))
	this.PPPid = uint32(ByteOrder.Uint32(data[40:44]))
	this.PPTgid = uint32(ByteOrder.Uint32(data[44:48]))
	this.NsPPPid = uint32(ByteOrder.Uint32(data[48:52]))
	this.NsPPTgid = uint32(ByteOrder.Uint32(data[52:56]))
	this.Uid = uint32(ByteOrder.Uint32(data[56:60]))
	this.Euid = uint32(ByteOrder.Uint32(data[60:64]))
	this.Gid = uint32(ByteOrder.Uint32(data[64:68]))
	this.Egid = uint32(ByteOrder.Uint32(data[68:72]))
	this.UtsInum = uint32(ByteOrder.Uint32(data[72:76]))
	this.Start_time = uint64(ByteOrder.Uint64(data[80:88]))
	this.Comm = string(bytes.TrimRight(data[88:104], "\x00"))
	this.Cmdline = string(bytes.Replace(bytes.TrimRight(data[104:360], "\x00"), []byte("\x00"), []byte("\x20"), -1))
	this.UtsName = string(bytes.TrimRight(data[360:424], "\x00"))
	return nil
}

func (this *BpfCallEvent) String() string {
	s := fmt.Sprintf("Cmd:%s, PID:%d, UID:%d, Comm:%s, cmdline:%s, utsName:%s", this.Type, this.Pid, this.Uid, this.Comm, this.Cmdline, this.UtsName)
	return s
}

func (this *BpfCallEvent) Clone() IEventStruct {
	return new(BpfCallEvent)
}
