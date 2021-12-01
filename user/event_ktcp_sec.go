package user

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

const TASK_COMM_LEN = 16

type EventIPV4 struct {
	TSUS  int64
	PID   uint32
	UID   uint32
	AF    uint32
	LAddr uint32
	LPort uint16
	RAddr uint32
	RPort uint16
	TASK  [TASK_COMM_LEN]byte
}

func (ei *EventIPV4) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &ei.TSUS); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.PID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.UID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.AF); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.LAddr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.LPort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.RAddr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.RPort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.TASK); err != nil {
		return
	}
	return nil
}

func (ei *EventIPV4) String() string {
	t_start := time.UnixMicro(ei.TSUS).Format("15:04:05")
	return fmt.Sprintf("start time:%s, PID:%d, UID:%d, AF:%d, TASK:%s", t_start, ei.PID, ei.UID, ei.AF, ei.TASK)
}

func (ei *EventIPV4) Clone() IEventStruct {
	return new(EventIPV4)
}

//IPv6
type EventIPV6 struct {
	TSUS  int64
	PID   uint32
	UID   uint32
	AF    uint16
	TASK  [TASK_COMM_LEN]byte
	RAddr [16]byte
	RPort uint16
}

func (ei *EventIPV6) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &ei.TSUS); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.PID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.UID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.AF); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.TASK); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.RAddr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.RPort); err != nil {
		return
	}
	return nil
}

func (ei *EventIPV6) String() string {
	t_start := time.UnixMicro(ei.TSUS).Format("15:04:05")
	return fmt.Sprintf("start time:%s, PID:%d, UID:%d, AF:%d, TASK:%s", t_start, ei.PID, ei.UID, ei.AF, ei.TASK)
}

func (ei *EventIPV6) Clone() IEventStruct {
	return new(EventIPV6)
}

//Other
type EventOther struct {
	TSUS int64
	PID  uint32
	UID  uint32
	AF   uint16
	TASK [TASK_COMM_LEN]byte
}

func (ei *EventOther) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &ei.TSUS); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.PID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.UID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.AF); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &ei.TASK); err != nil {
		return
	}
	return nil
}

func (ei *EventOther) String() string {
	t_start := time.UnixMicro(ei.TSUS).Format("15:04:05")
	return fmt.Sprintf("start time:%s, PID:%d, UID:%d, AF:%d, TASK:%s", t_start, ei.PID, ei.UID, ei.AF, ei.TASK)
}

func (ei *EventOther) Clone() IEventStruct {
	return new(EventOther)
}
