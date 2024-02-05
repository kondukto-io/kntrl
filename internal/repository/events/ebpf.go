package events

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/kondukto-io/kntrl/internal/core/port/event"
)

type EbpfRepo struct {
	Collection *ebpf.Collection
	Spec       *ebpf.CollectionSpec
}

func New() event.Repository {
	return &EbpfRepo{}
}

func (e *EbpfRepo) Load(prog []byte) error {
	return e.load(prog)
}

func (e *EbpfRepo) Put(mapName string, key, value interface{}) error {
	return e.Collection.Maps[mapName].Put(key, value)
}

func (e *EbpfRepo) ReadByPerf(mapName string) (*perf.Reader, error) {
	mapDetail := e.Collection.Maps[mapName]
	return perf.NewReader(mapDetail, 4096)
}

func (e *EbpfRepo) GetSpecPrograms() map[string]*ebpf.ProgramSpec {
	return e.Spec.Programs
}

func (e *EbpfRepo) GetSingleProgramBySpec(spec string) *ebpf.Program {
	return e.Collection.Programs[spec]
}

func (e *EbpfRepo) Clean() {
	e.Collection.Close()
}
