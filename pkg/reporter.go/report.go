package reporter

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/logger"
	"github.com/kondukto-io/kntrl/utils"
	"github.com/pterm/pterm"
)

// Reporter is a reporter for events
type Reporter struct {
	events         []domain.IP4Event
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

// AddEvent adds an event to the reporter
func (r *Reporter) AddEvent(event domain.IP4Event) {
	var address = utils.IntToIP(event.Daddr).String()
	var hash = hash(address)

	if _, ok := r.eventsHashMap[hash]; ok {
		logger.Log.Debugf("event with address [%s] already exists")
		return
	}

	r.events = append(r.events, event)
	r.eventsHashMap[hash] = true
}

// PrintTable prints the reporter table
func (r *Reporter) PrintTable() {
	data := pterm.TableData{
		{"Pid", "Comm", "Proto", "Domain", "Destination Addr", "Policy"},
	}

	for _, v := range r.events {
		res := make([]string, 0)
		res = append(res, strconv.FormatUint(uint64(v.Pid), 10))
		res = append(res, v.Comm)
		res = append(res, v.Proto)
		res = append(res, v.Daddr)
		//res = append(res, v.Daddr.String())
		res = append(res, fmt.Sprintf("%s:%d", utils.IntToIP(v.Daddr).String(), v.Dport))
		res = append(res, strconv.FormatBool(v.Policy))
		data = append(data, res)
	}

	var tablePrinter = pterm.DefaultTable.WithHasHeader().WithRowSeparator("-").WithHeaderRowSeparator("-").WithData(data)

	fmt.Println("------------------------------\n")

	tablePrinter.Render()

	fmt.Println("------------------------------\n")

	table, err := tablePrinter.Srender()
	if err != nil {
		log.Fatalf("Failed to render table: %s", err)
	}

	file, err := r.openReportFile()
	if err != nil {
		log.Fatalf("Failed to open file: %s", err)
	}

	_, err = file.WriteString(table)
	if err != nil {
		log.Fatalf("Failed writing to file: %s", err)
	}

	logger.Log.Infof("report file can be found here: %s", r.outputFileName)

	file.Close()
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
