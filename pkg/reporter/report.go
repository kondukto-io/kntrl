package reporter

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/pterm/pterm"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/logger"
)

const defaultFile = "/tmp/kntrl.out"

// Reporter is a reporter for events
type Reporter struct {
	mu             sync.Mutex
	events         []domain.ReportEvent
	eventsHashMap  map[string]bool
	processEvents  []domain.ProcessReportEvent
	dnsEvents      []domain.DNSReportEvent
	fileEvents     []domain.FileReportEvent
	Err            error
	outputFileName string
	file           *os.File
}

// NewReporter returns a new reporter
func NewReporter(outputFileName string) *Reporter {
	if outputFileName == "" {
		outputFileName = defaultFile
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

func LoadAndPrint() error {
	f, err := os.OpenFile(defaultFile, os.O_RDONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer f.Close()

	r := Reporter{
		file:           f,
		outputFileName: defaultFile,
	}

	rd := bufio.NewReader(f)
	for {
		line, err := rd.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		event := domain.ReportEvent{}
		err = json.Unmarshal([]byte(line), &event)
		if err != nil {
			return err
		}
		r.events = append(r.events, event)
	}

	r.PrintReportTable()
	return nil
}

// WriteEvent adds an event to the report file
func (r *Reporter) WriteEvent(event domain.ReportEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var address = event.DestinationAddress + ":" + fmt.Sprint(event.DestinationPort)
	var h = hash(address)

	if _, ok := r.eventsHashMap[h]; ok {
		logger.Log.Debugf("event with address [%s] already exists", address)
		return
	}

	r.events = append(r.events, event)
	r.eventsHashMap[h] = true

	eventData, err := json.Marshal(event)
	if err != nil {
		logger.Log.Errorf("failed to marshal event: %v", err)
		return
	}

	if _, err = r.file.WriteString(string(eventData) + "\n"); err != nil {
		logger.Log.Errorf("failed to write event to file: %s %v", r.file.Name(), err)
	}
}

// WriteFileEvent adds a file access event to the report
func (r *Reporter) WriteFileEvent(event domain.FileReportEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.fileEvents = append(r.fileEvents, event)

	eventData, err := json.Marshal(event)
	if err != nil {
		logger.Log.Errorf("failed to marshal file event: %v", err)
		return
	}

	if _, err = r.file.WriteString(string(eventData) + "\n"); err != nil {
		logger.Log.Errorf("failed to write file event to file: %s %v", r.file.Name(), err)
	}
}

// WriteDNSEvent adds a DNS event to the report
func (r *Reporter) WriteDNSEvent(event domain.DNSReportEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.dnsEvents = append(r.dnsEvents, event)

	eventData, err := json.Marshal(event)
	if err != nil {
		logger.Log.Errorf("failed to marshal dns event: %v", err)
		return
	}

	if _, err = r.file.WriteString(string(eventData) + "\n"); err != nil {
		logger.Log.Errorf("failed to write dns event to file: %s %v", r.file.Name(), err)
	}
}

// WriteProcessEvent adds a process event to the report
func (r *Reporter) WriteProcessEvent(event domain.ProcessReportEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.processEvents = append(r.processEvents, event)

	eventData, err := json.Marshal(event)
	if err != nil {
		logger.Log.Errorf("failed to marshal process event: %v", err)
		return
	}

	if _, err = r.file.WriteString(string(eventData) + "\n"); err != nil {
		logger.Log.Errorf("failed to write process event to file: %s %v", r.file.Name(), err)
	}
}

// Close closes the report file
func (r *Reporter) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.file.Close(); err != nil {
		logger.Log.Errorf("failed to close report file: %v", err)
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
	r.mu.Lock()
	defer r.mu.Unlock()

	fmt.Print("\n\n")
	data := pterm.TableData{
		{"Pid", "Comm", "Proto", "Domain", "Destination Addr", "Policy"},
	}

	for _, v := range r.events {
		domain := strings.Join(v.Domains, ", ")
		if domain == "" {
			domain = "."
		}
		res := []string{
			strconv.FormatUint(uint64(v.ProcessID), 10),
			v.TaskName,
			v.Protocol,
			domain,
			fmt.Sprintf("%s:%d", v.DestinationAddress, v.DestinationPort),
			v.Policy,
		}
		data = append(data, res)
	}

	pterm.DefaultTable.WithHasHeader().WithRowSeparator("-").WithHeaderRowSeparator("-").WithData(data).Render()
}

func (r *Reporter) PrintFileTable() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.fileEvents) == 0 {
		return
	}

	fmt.Print("\n\n")
	data := pterm.TableData{
		{"Pid", "Comm", "Filename", "Flags"},
	}

	for _, v := range r.fileEvents {
		res := []string{
			strconv.FormatUint(uint64(v.ProcessID), 10),
			v.Comm,
			v.Filename,
			strconv.FormatInt(int64(v.Flags), 10),
		}
		data = append(data, res)
	}

	pterm.DefaultTable.WithHasHeader().WithRowSeparator("-").WithHeaderRowSeparator("-").WithData(data).Render()
}

func (r *Reporter) PrintDNSTable() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.dnsEvents) == 0 {
		return
	}

	// Deduplicate: collect unique domains and their DNS servers
	type dnsEntry struct {
		domain string
		server string
	}
	seen := make(map[dnsEntry]bool)
	var unique []dnsEntry

	for _, v := range r.dnsEvents {
		if v.QueryDomain == "" {
			continue
		}
		e := dnsEntry{domain: v.QueryDomain, server: v.DNSServer}
		if !seen[e] {
			seen[e] = true
			unique = append(unique, e)
		}
	}

	if len(unique) == 0 {
		return
	}

	fmt.Print("\n\n")
	data := pterm.TableData{
		{"Domain", "DNS Server"},
	}

	for _, e := range unique {
		data = append(data, []string{e.domain, e.server})
	}

	pterm.DefaultTable.WithHasHeader().WithRowSeparator("-").WithHeaderRowSeparator("-").WithData(data).Render()
}

func (r *Reporter) PrintProcessTable() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.processEvents) == 0 {
		return
	}

	fmt.Print("\n\n")
	data := pterm.TableData{
		{"Pid", "PPid", "Type", "Comm", "Filename"},
	}

	for _, v := range r.processEvents {
		res := []string{
			strconv.FormatUint(uint64(v.ProcessID), 10),
			strconv.FormatUint(uint64(v.ParentPID), 10),
			v.EventType,
			v.Comm,
			v.Filename,
		}
		data = append(data, res)
	}

	pterm.DefaultTable.WithHasHeader().WithRowSeparator("-").WithHeaderRowSeparator("-").WithData(data).Render()
}

func hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))

	return hex.EncodeToString(hasher.Sum(nil))
}
