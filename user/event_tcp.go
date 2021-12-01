package user

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strconv"
	"time"
)

type TCPEvent struct {
	StartNS int64
	EndNS   int64
	PID     uint32
	LAddr   uint32
	LPort   uint16
	RAddr   uint32
	RPort   uint16
	Flags   uint8
	Rx      uint64
	Tx      uint64
	Comm    [16]byte
	Family  uint16
	UID     uint16
}

func (e *TCPEvent) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &e.StartNS); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.EndNS); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.PID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.LAddr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.LPort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.RAddr); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.RPort); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Flags); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Rx); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Tx); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Comm); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.Family); err != nil {
		return
	}

	err = binary.Read(buf, binary.LittleEndian, &e.UID)
	return nil
}

func (te *TCPEvent) String() string {
	t_end := time.Now()
	t_start := t_end.Add(-time.Nanosecond * (time.Duration(te.EndNS - te.StartNS))).Format("15:04:05")

	dest := inet_ntop(te.RAddr) + ":" + strconv.Itoa(int(te.RPort))

	var header string
	var args []interface{}

	header = "start time:%s, family:%s, PID:%d, command:%s, UID:%d, rx:%d, tx:%d, dest:%s, source:%s, type:%s, result:%s"
	var family string
	switch {
	case te.Family == AF_INET:
		family = "AF_INET"
	case te.Family == AF_INET6:
		family = "AF_INET6"
	case te.Family == AF_FILE:
		family = "AF_FILE"
	default:
		family = fmt.Sprintf("%d", te.Family)
	}

	outStr := "OUT"
	if te.Flags&1 == 0 {
		outStr = "IN"
	}

	sucStr := "True"
	if te.Flags&0x10 == 0 {
		sucStr = "False"
	}

	args = []interface{}{t_start, family, te.PID, te.Comm, te.UID, te.Rx, te.Tx, dest, inet_ntop(te.LAddr), outStr, sucStr}
	s := fmt.Sprintf(header, args...)
	return s
}

func (e *TCPEvent) Clone() IEventStruct {
	return new(TCPEvent)
}
