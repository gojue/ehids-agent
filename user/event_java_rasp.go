package user

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	MODE_FORK        = 1
	MODE_POSIX_SPAWN = 2
	MODE_VFORK       = 3
	MODE_CLONE       = 4
)

type JavaJDKExecPeEvent struct {
	Pid  uint32
	Mode uint64
	File [128]byte
}

func (e *JavaJDKExecPeEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &e.Pid); err != nil {
		err = fmt.Errorf("read e.Pid:%v", err)
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Mode); err != nil {
		err = fmt.Errorf("read e.Mode:%v", err)
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.File); err != nil {
		return
	}
	return nil
}

func (ei *JavaJDKExecPeEvent) String() string {
	var m string = "UNKNOW"
	switch ei.Mode {
	case 1:
		m = "MODE_FORK"
	case 2:
		m = "MODE_POSIX_SPAWN"
	case 3:
		m = "MODE_VFORK"
	case 4:
		m = "MODE_CLONE"
	}
	s := fmt.Sprintf(fmt.Sprintf("JAVA RASP exec and fork. PID:%d, command:%s, mode:%s", ei.Pid, ei.File, m))
	return s
}

func (ei *JavaJDKExecPeEvent) Clone() IEventStruct {
	return new(JavaJDKExecPeEvent)
}
