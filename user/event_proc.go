package user

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type ForkProcEvent struct {
	eventType int32

	ChildPid   uint32
	ChildTgid  uint32
	ParentPid  uint32
	ParentTgid uint32

	GrandParentPid  uint32
	GrandParentTgid uint32
	Uid             uint32
	Gid             uint32

	Cwd_level  uint32
	UtsInum    uint32
	Start_time uint64
	Comm       [16]byte
	Cmdline    [128]byte
	Path       [128]byte
}

const (
	PROC_EVENT_FORK = 0x00000001 // fork() events
	PROC_EVENT_EXEC = 0x00000002 // exec() events
	PROC_EVENT_EXIT = 0x00000003 // exit() events
)

func (fe *ForkProcEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)

	if err = binary.Read(buf, binary.LittleEndian, &fe.ChildPid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &fe.ChildTgid); err != nil {
		return
	}

	if err = binary.Read(buf, binary.LittleEndian, &fe.ParentPid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &fe.ParentTgid); err != nil {
		return
	}

	if err = binary.Read(buf, binary.LittleEndian, &fe.GrandParentPid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &fe.GrandParentTgid); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &fe.Uid); err != nil {
		return
	}

	if err = binary.Read(buf, binary.LittleEndian, &fe.Gid); err != nil {
		return
	}

	if err = binary.Read(buf, binary.LittleEndian, &fe.Cwd_level); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &fe.UtsInum); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &fe.Start_time); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &fe.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &fe.Cmdline); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &fe.Path); err != nil {
		return
	}

	return nil
}

func (fe *ForkProcEvent) String() string {
	var s string
	s = fmt.Sprintf(" fork event,childpid:%d, childtgid:%d,  parentpid:%d, parenttgid:%d,  grandparentpid:%d, grandparentgid:%d, cwd_level:%d, comm:%s, cmdline:%s, filepath:%s, start_time:%d, uid:%d,  gid:%d,uts_ium:%d,\n",
		fe.ChildPid, fe.ChildTgid, fe.ParentPid, fe.ParentTgid, fe.GrandParentPid, fe.GrandParentTgid,
		fe.Cwd_level, fe.Comm, fe.Cmdline, fe.Path, fe.Start_time, fe.Uid, fe.Gid, fe.UtsInum)
	return s
}

func (fe *ForkProcEvent) Clone() IEventStruct {
	return new(ForkProcEvent)
}

//反转函数
func get_cwd(level uint32, str [10][16]byte) string {
	if level == 0 {
		return ""
	}
	cwd := ""
	for i := level; i > 0; i-- {
		if len(str[level]) == 0 {
			continue
		}
		cwd += string(str[i][:])
		if i != 0 && i != level {
			cwd += "/"
		}
	}
	return cwd
}
