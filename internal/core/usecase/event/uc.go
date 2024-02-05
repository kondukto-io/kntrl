package event

import (
	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/internal/core/port/event"
)

type useCase struct {
	eventRepo event.Repository
}

func New(eventRepo event.Repository) event.UseCase {
	return &useCase{
		eventRepo: eventRepo,
	}
}

// PutModeMap puts values into ModeMap Collection
func (e *useCase) PutModeMap(key, value interface{}) error {
	return e.eventRepo.Put(domain.EBPFCollectionMapMode, key, value)
}

// PutAllowMap puts values into AllowMap Collection
func (e *useCase) PutAllowMap(key, value interface{}) error {
	return e.eventRepo.Put(domain.EBPFCollectionMapAllow, key, value)
}

// PutIPV4EventsMap puts values into IPV4Event Collection
func (e *useCase) PutIPV4EventsMap(key, value interface{}) error {
	return e.eventRepo.Put(domain.EBPFCollectionMapIPV4Events, key, value)
}

// PutIPV4ClosedEventsMap puts values into IPV4ClosedEvent Collection
func (e *useCase) PutIPV4ClosedEventsMap(key, value interface{}) error {
	return e.eventRepo.Put(domain.EBPFCollectionMapIPV4ClosedEvents, key, value)
}
