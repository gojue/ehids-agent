package user

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const HOST_COMM_LEN = 80

type DNSEVENT struct {
	PID      uint32
	UID      uint32
	AF       uint32
	AddrIpv4 uint32
	AddrIpv6 [16]byte
	HOST     [HOST_COMM_LEN]byte
}

func (e *DNSEVENT) Decode(payload []byte) (err error) {
	buf := bytes.NewBuffer(payload)
	if err = binary.Read(buf, binary.LittleEndian, &e.PID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.UID); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.AF); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.AddrIpv4); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.AddrIpv6); err != nil {
		return
	}
	if err = binary.Read(buf, binary.LittleEndian, &e.HOST); err != nil {
		return
	}
	return nil
}

func (ei *DNSEVENT) String() string {
	var a int
	for _, b := range ei.HOST {
		if b == 0 {
			break
		}
		a++
	}
	var af string
	switch ei.AF {
	case 2:
		af = "AF_INET"
	case 10:
		af = "AF_INET6"
	default:
		af = fmt.Sprintf("UNKNOW_%d", ei.AF)
	}
	s := fmt.Sprintf(fmt.Sprintf(" PID:%d, UID:%d, AF:%s, IP:%s, HOST:%s", ei.PID, ei.UID, af, inet_ntop(ei.AddrIpv4), string(ei.HOST[:a])))
	return s
}

func (ei *DNSEVENT) Clone() IEventStruct {
	return new(DNSEVENT)
}
