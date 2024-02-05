package event

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
)

type Repository interface {
	Load(program []byte) error
	ReadByPerf(mapName string) (*perf.Reader, error)
	Put(mapName string, key, value interface{}) error
	GetSpecPrograms() map[string]*ebpf.ProgramSpec
	GetSingleProgramBySpec(spec string) *ebpf.Program
	Clean()
}

type UseCase interface {
	PutModeMap(key, value interface{}) error
	PutAllowMap(key, value interface{}) error
	PutIPV4EventsMap(key, value interface{}) error
	PutIPV4ClosedEventsMap(key, value interface{}) error
}
