package reporter

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/logger"
)

// Reporter is a reporter for events
type Reporter struct {
	events         []domain.ReportEvent
	eventsHashMap  map[string]bool
	Err            error
	outputFileName string
}

type event struct {
	Pid    uint32
	Comm   string
	Sport  uint16
	Dport  uint16
	Saddr  net.IP
	Daddr  net.IP
	Domain []string
	Proto  string
	Policy bool
}

// NewReporter returns a new reporter
func NewReporter(outputFileName string) Reporter {
	if outputFileName == "" {
		outputFileName = "/tmp/kntrl.out"
		logger.Log.Debugf("using the default output file: %s", outputFileName)
	}

	var report = Reporter{
		eventsHashMap:  make(map[string]bool, 0),
		outputFileName: outputFileName,
	}

	file, err := report.openReportFile()
	if err != nil {
		report.Err = fmt.Errorf("failed to open report file: %w", err)
		return report
	}

	file.Close()

	return report
}

// WriteEvent adds an event to the report file
func (r *Reporter) WriteEvent(event domain.ReportEvent) {
	var address = event.DestinationAddress + ":" + fmt.Sprint(event.DestinationPort)
	var hash = hash(address)

	if _, ok := r.eventsHashMap[hash]; ok {
		logger.Log.Debugf("event with address [%s] already exists", address)
		return
	}

	r.eventsHashMap[hash] = true

	eventData, err := json.MarshalIndent(event, "", "	")
	if err != nil {
		log.Fatalf("failed to marshal: %s", err)
	}

	file, err := r.openReportFile()
	if err != nil {
		log.Fatalf("failed to open file: %s", err)
	}
	defer file.Close()

	_, err = file.Write(eventData)
	if err != nil {
		log.Fatalf("failed writing to file: %s", err)
	}
}

func (r *Reporter) openReportFile() (*os.File, error) {
	file, err := os.Open(r.outputFileName)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to stat output file: %w", err)
		}

		_, err := os.Create(r.outputFileName)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
	}

	return file, nil
}

func hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))

	return hex.EncodeToString(hasher.Sum(nil))
}
