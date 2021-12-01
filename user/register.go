package user

import "fmt"

var ProbeMaps = make(map[string]IBPFProbe)

func Register(p IBPFProbe) {
	if p == nil {
		panic("Register probe is nil")
	}
	name := p.ProbeName()
	if _, dup := ProbeMaps[name]; dup {
		panic(fmt.Sprintf("Register called twice for probe %s", name))
	}
	ProbeMaps[name] = p
}
