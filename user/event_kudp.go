package user

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	dns "github.com/cirocosta/rawdns/lib"
)

type UDPEvent struct {
	pid    uint32
	comm   string
	packet []byte
	ask    []question
	ans    []answers
}

type question struct {
	qname  string
	qclass string
	qtype  string
}

type answers struct {
	qtype string
	qinfo string
}

func (e *UDPEvent) Decode(payload []byte) (err error) {
	var pid uint32
	err = binary.Read(bytes.NewBuffer(payload), binary.LittleEndian, &pid)
	if err != nil {
		fmt.Printf("failed to decode received data: %s\n", err)
		return
	}
	e.comm = string(payload[4:20])
	e.packet = payload[20:]
	//fmt.Printf("\n>>> %d - %s - %d\n", pid, comm, len(packet))
	var m dns.Message
	err = dns.UnmarshalMessage(e.packet, &m)
	if err != nil {
		return fmt.Errorf("failed to decode packet: %s\n", err)
	}

	e.ask = make([]question, len(m.Questions))
	for i := 0; i < len(m.Questions); i++ {
		q := m.Questions[i]
		e.ask[i] = question{q.QNAME, fmt.Sprintf("%d", q.QCLASS), fmt.Sprintf("%d", q.QTYPE)}
		//fmt.Println("===ASK===", q.QNAME, q.QCLASS, q.QTYPE)
	}

	e.ans = make([]answers, len(m.Answers))

	for i := 0; i < len(m.Answers); i++ {
		r := m.Answers[i]
		var an = answers{}
		if r.TYPE == dns.QTypeA {
			an.qtype = "QTypeA"
			an.qinfo = fmt.Sprintf("[A] :%s", net.IP(r.RDATA))
		} else if r.TYPE == dns.QTypeCNAME {
			an.qtype = "QTypeCNAME"
			an.qinfo = fmt.Sprintf("[CNAME] :%s", string(r.RDATA))
			//fmt.Println("[CNAME]", string(r.RDATA))
		} else {
			//fmt.Println("===ANS===", r.CLASS, r.NAME, r.TYPE, r.RDATA)
			an.qtype = "ANS"
			an.qinfo = fmt.Sprintf("===ANS=== %d, %s, %d, %s", uint16(r.CLASS), r.NAME, uint16(r.TYPE), r.RDATA)
		}
		e.ans[i] = an
	}
	/**/
	return nil
}

func (te *UDPEvent) String() string {
	var s string
	s = fmt.Sprintf("PID:%d, comm:%s, ", te.pid, te.comm)
	for _, ask := range te.ask {
		s += fmt.Sprintf("qname:%s, qclass:%s, qtype:%s.\t", ask.qname, ask.qclass, ask.qtype)
	}

	for _, ans := range te.ans {
		s += fmt.Sprintf("qtype:%s, qinfo:%s.\t", ans.qtype, ans.qinfo)
	}

	return s
}

func (e *UDPEvent) Clone() IEventStruct {
	return new(UDPEvent)
}
