package reporter

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/pterm/pterm"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/logger"
)

// Reporter is a reporter for events
type Reporter struct {
	events         []domain.ReportEvent
	eventsHashMap  map[string]bool
	Err            error
	outputFileName string
	file           *os.File
}

// NewReporter returns a new reporter
func NewReporter(outputFileName string) *Reporter {
	if outputFileName == "" {
		outputFileName = "/tmp/kntrl.out"
		logger.Log.Debugf("using the default output file: %s", outputFileName)
	}

	var report = &Reporter{
		eventsHashMap:  make(map[string]bool, 0),
		outputFileName: outputFileName,
	}

	file, err := report.openReportFile()
	if err != nil {
		report.Err = fmt.Errorf("failed to open report file: %w", err)
		return report
	}

	report.file = file

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

	r.events = append(r.events, event)
	r.eventsHashMap[hash] = true

	eventData, err := json.Marshal(event)
	if err != nil {
		log.Fatalf("failed to marshal: %v", err)
	}

	//println(string(eventData)) //
	_, err = r.file.WriteString(string(eventData) + "\n")
	if err != nil {
		log.Fatalf("failed to write an event to file: %s %v", r.file.Name(), err)
	}
}

// Close closes the report file
func (r *Reporter) Close() {
	if err := r.file.Close(); err != nil {
		log.Fatalf("failed to close file: %v", err)
	}
}

func (r *Reporter) openReportFile() (*os.File, error) {
	file, err := os.OpenFile(r.outputFileName, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to stat output file: %w", err)
		}

		if err := os.MkdirAll(filepath.Dir(r.outputFileName), os.ModePerm); err != nil && !os.IsExist(err) {
			return nil, fmt.Errorf("failed to create output directory: %w", err)
		}

		file, err = os.Create(r.outputFileName)
		if err != nil {
			return nil, fmt.Errorf("failed to create output file: %w", err)
		}
	}

	return file, nil
}

func (r *Reporter) PrintReportTable() {
	fmt.Print("\n\n")
	data := pterm.TableData{
		{"Pid", "Comm", "Proto", "Domain", "Destination Addr", "Policy"},
	}

	for _, v := range r.events {
		res := make([]string, 0, len(v.Domains)+5)
		res = append(res, strconv.FormatUint(uint64(v.ProcessID), 10))
		res = append(res, v.TaskName)
		res = append(res, v.Protocol)
		res = append(res, v.Domains...)
		res = append(res, fmt.Sprintf("%s:%d", v.DestinationAddress, v.DestinationPort))
		res = append(res, v.Policy)
		data = append(data, res)
	}

	pterm.DefaultTable.WithHasHeader().WithRowSeparator("-").WithHeaderRowSeparator("-").WithData(data).Render()
}

func hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))

	return hex.EncodeToString(hasher.Sum(nil))
}
