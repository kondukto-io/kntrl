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
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/pterm/pterm"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/logger"
)

const defaultFile = "/tmp/kntrl.out"
const selfBinaryName = "kntrl"

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
	writer         *bufio.Writer
	selfPID        uint32
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
	report.writer = bufio.NewWriterSize(file, 64*1024)

	return report
}

// SetSelfPID records kntrl's own PID so its process tree can be filtered from output.
func (r *Reporter) SetSelfPID(pid uint32) {
	r.selfPID = pid
}

// selfPIDs returns the set of PIDs belonging to kntrl and all its descendants.
func (r *Reporter) selfPIDs() map[uint32]bool {
	pids := map[uint32]bool{r.selfPID: true}
	// Events are in chronological order, so a single pass propagates correctly.
	for _, ev := range r.processEvents {
		if ev.Comm == selfBinaryName {
			pids[ev.ProcessID] = true
		}
		if pids[ev.ParentPID] {
			pids[ev.ProcessID] = true
		}
	}
	return pids
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

	if _, err = r.writer.WriteString(string(eventData) + "\n"); err != nil {
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

	if _, err = r.writer.WriteString(string(eventData) + "\n"); err != nil {
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

	if _, err = r.writer.WriteString(string(eventData) + "\n"); err != nil {
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

	if _, err = r.writer.WriteString(string(eventData) + "\n"); err != nil {
		logger.Log.Errorf("failed to write process event to file: %s %v", r.file.Name(), err)
	}
}

// Close flushes the buffered writer and closes the report file.
func (r *Reporter) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if err := r.writer.Flush(); err != nil {
		logger.Log.Errorf("failed to flush report writer: %v", err)
	}
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
		{"Pid", "Comm", "Filename", "Op", "Policy", "Env Vars"},
	}

	for _, v := range r.fileEvents {
		envVars := strings.Join(v.MatchedEnvVars, ", ")
		if envVars == "" {
			envVars = "."
		}
		opStr := v.Operation
		if opStr == "" {
			opStr = "open"
		}
		res := []string{
			strconv.FormatUint(uint64(v.ProcessID), 10),
			v.Comm,
			v.Filename,
			opStr,
			v.Policy,
			envVars,
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

func (r *Reporter) PrintProcessTable(pretty bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.processEvents) == 0 {
		return
	}

	if pretty {
		r.printProcessTree()
	} else {
		r.printProcessFlat()
	}
}

func (r *Reporter) printProcessFlat() {
	selfSet := r.selfPIDs()

	fmt.Print("\n\n")
	data := pterm.TableData{
		{"Pid", "PPid", "Type", "Comm", "Args", "Policy"},
	}

	for _, v := range r.processEvents {
		if selfSet[v.ProcessID] {
			continue
		}
		policyStr := v.Policy
		if policyStr == "" {
			policyStr = "."
		}
		res := []string{
			strconv.FormatUint(uint64(v.ProcessID), 10),
			strconv.FormatUint(uint64(v.ParentPID), 10),
			v.EventType,
			v.Comm,
			v.Args,
			policyStr,
		}
		data = append(data, res)
	}

	pterm.DefaultTable.WithHasHeader().WithRowSeparator("-").WithHeaderRowSeparator("-").WithData(data).Render()
}

func (r *Reporter) printProcessTree() {
	// Merge fork + exec events per pid.
	// Fork provides reliable ppid (from tracepoint args).
	// Exec provides args, filename, comm.
	// Events can arrive in any order (exec before fork is possible).
	type procNode struct {
		pid     uint32
		ppid    uint32
		comm    string
		args    string
		policy  string
		hasFork bool
	}

	nodeMap := make(map[uint32]*procNode)
	var order []uint32

	selfSet := r.selfPIDs()

	for _, ev := range r.processEvents {
		if selfSet[ev.ProcessID] {
			continue
		}
		n, exists := nodeMap[ev.ProcessID]
		if !exists {
			n = &procNode{pid: ev.ProcessID, ppid: ev.ParentPID, comm: ev.Comm}
			nodeMap[ev.ProcessID] = n
			order = append(order, ev.ProcessID)
		}

		if ev.EventType == "fork" {
			// Fork ppid comes from tracepoint args — always reliable
			n.ppid = ev.ParentPID
			n.hasFork = true
			if n.comm == "" {
				n.comm = ev.Comm
			}
		} else {
			// Exec provides display data (args, comm, policy)
			n.comm = ev.Comm
			n.args = ev.Args
			if ev.Policy != "" {
				n.policy = ev.Policy
			}
			// Only use exec's ppid if we never got a fork event
			if !n.hasFork {
				n.ppid = ev.ParentPID
			}
		}
	}

	// Build children map
	children := make(map[uint32][]uint32)
	for _, pid := range order {
		n := nodeMap[pid]
		if n == nil {
			continue
		}
		children[n.ppid] = append(children[n.ppid], pid)
	}

	// Find roots: processes whose ppid is not in nodeMap
	var roots []uint32
	for _, pid := range order {
		n := nodeMap[pid]
		if n == nil {
			continue
		}
		if _, ok := nodeMap[n.ppid]; !ok {
			roots = append(roots, pid)
		}
	}

	sort.Slice(roots, func(i, j int) bool { return roots[i] < roots[j] })

	fmt.Print("\n\n")
	pterm.DefaultHeader.WithBackgroundStyle(pterm.NewStyle(pterm.BgDefault)).
		WithTextStyle(pterm.NewStyle(pterm.FgLightCyan, pterm.Bold)).
		Println("Process Tree")

	var printTree func(pid uint32, prefix string, isLast bool)
	printTree = func(pid uint32, prefix string, isLast bool) {
		n := nodeMap[pid]
		if n == nil {
			return
		}

		connector := "├── "
		if isLast {
			connector = "└── "
		}
		if prefix == "" {
			connector = ""
		}

		display := n.args
		if display == "" {
			display = n.comm
		}

		policyTag := ""
		if n.policy == "block" {
			policyTag = " [BLOCKED]"
		}

		fmt.Printf("%s%s[%d] %s%s\n", prefix, connector, n.pid, display, policyTag)

		kids := children[pid]
		sort.Slice(kids, func(i, j int) bool { return kids[i] < kids[j] })

		childPrefix := prefix
		if prefix != "" {
			if isLast {
				childPrefix += "    "
			} else {
				childPrefix += "│   "
			}
		}

		for i, child := range kids {
			printTree(child, childPrefix, i == len(kids)-1)
		}
	}

	for i, root := range roots {
		printTree(root, "", i == len(roots)-1)
	}
	fmt.Println()
}

func (r *Reporter) PrintSensitiveAccessReport() {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.fileEvents) == 0 {
		return
	}

	// Aggregate by PID+Comm
	type processKey struct {
		pid  uint32
		comm string
	}
	type accessSummary struct {
		files   []string
		envVars []string
	}

	seen := make(map[processKey]*accessSummary)
	var order []processKey

	for _, ev := range r.fileEvents {
		k := processKey{pid: ev.ProcessID, comm: ev.Comm}
		s, exists := seen[k]
		if !exists {
			s = &accessSummary{}
			seen[k] = s
			order = append(order, k)
		}
		// Dedup files (skip synthetic [inherited] marker)
		if ev.Filename != "[inherited]" && !containsStr(s.files, ev.Filename) {
			s.files = append(s.files, ev.Filename)
		}
		// Collect unique env vars
		for _, v := range ev.MatchedEnvVars {
			if !containsStr(s.envVars, v) {
				s.envVars = append(s.envVars, v)
			}
		}
	}

	// Render table
	fmt.Print("\n\n")
	pterm.DefaultHeader.WithBackgroundStyle(pterm.NewStyle(pterm.BgDefault)).
		WithTextStyle(pterm.NewStyle(pterm.FgLightRed, pterm.Bold)).
		Println("Sensitive Access Report")

	data := pterm.TableData{
		{"Pid", "Comm", "Files Accessed", "Env Vars Detected"},
	}
	for _, k := range order {
		s, ok := seen[k]
		if !ok {
			continue
		}
		files := strings.Join(s.files, ", ")
		if files == "" {
			files = "."
		}
		envVars := strings.Join(s.envVars, ", ")
		if envVars == "" {
			envVars = "."
		}
		data = append(data, []string{
			strconv.FormatUint(uint64(k.pid), 10),
			k.comm,
			files,
			envVars,
		})
	}
	pterm.DefaultTable.WithHasHeader().WithRowSeparator("-").WithHeaderRowSeparator("-").WithData(data).Render()
}

// GetEvents returns a copy of all network report events.
func (r *Reporter) GetEvents() []domain.ReportEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]domain.ReportEvent, len(r.events))
	copy(out, r.events)
	return out
}

// GetProcessEvents returns a copy of all process report events.
func (r *Reporter) GetProcessEvents() []domain.ProcessReportEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]domain.ProcessReportEvent, len(r.processEvents))
	copy(out, r.processEvents)
	return out
}

// GetDNSEvents returns a copy of all DNS report events.
func (r *Reporter) GetDNSEvents() []domain.DNSReportEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]domain.DNSReportEvent, len(r.dnsEvents))
	copy(out, r.dnsEvents)
	return out
}

// GetFileEvents returns a copy of all file report events.
func (r *Reporter) GetFileEvents() []domain.FileReportEvent {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make([]domain.FileReportEvent, len(r.fileEvents))
	copy(out, r.fileEvents)
	return out
}

// GetSummaryCounts returns aggregate counts from the collected events.
func (r *Reporter) GetSummaryCounts() domain.SummaryCounts {
	r.mu.Lock()
	defer r.mu.Unlock()

	counts := domain.SummaryCounts{
		TotalNetwork: len(r.events),
		TotalProcess: len(r.processEvents),
		TotalDNS:     len(r.dnsEvents),
		TotalFile:    len(r.fileEvents),
	}
	for _, e := range r.events {
		if e.Policy == domain.EventPolicyStatusBlock {
			counts.Blocked++
		} else {
			counts.Passed++
		}
	}
	return counts
}

func containsStr(sl []string, s string) bool {
	for _, v := range sl {
		if v == s {
			return true
		}
	}
	return false
}

func hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))

	return hex.EncodeToString(hasher.Sum(nil))
}
