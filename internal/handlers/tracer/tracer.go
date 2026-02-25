package tracer

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/kondukto-io/kntrl/bundle"
	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/ci"
	"github.com/kondukto-io/kntrl/pkg/cloud"
	"github.com/kondukto-io/kntrl/pkg/config"
	ebpfman "github.com/kondukto-io/kntrl/pkg/ebpf"
	"github.com/kondukto-io/kntrl/pkg/logger"
	"github.com/kondukto-io/kntrl/pkg/parser"
	"github.com/kondukto-io/kntrl/pkg/policy"
	"github.com/kondukto-io/kntrl/pkg/proctree"
	"github.com/kondukto-io/kntrl/pkg/reporter"
	"github.com/kondukto-io/kntrl/pkg/utils"
	"github.com/kondukto-io/kntrl/pkg/webhook"
)

var (
	//go:embed bpf_bpfel_x86.o
	prog []byte
)

const (
	rootCgroup = "/sys/fs/cgroup"
	progName   = "kntrl"
)

// tracePointAttach maps eBPF program names to their tracepoint group/name pairs.
var tracePointAttach = map[string][2]string{
	"inet_sock_set_state": {"sock", "inet_sock_set_state"},
	"trace_exec":          {"sched", "sched_process_exec"},
	"trace_fork":          {"sched", "sched_process_fork"},
	"trace_openat":        {"syscalls", "sys_enter_openat"},
	"trace_renameat2":     {"syscalls", "sys_enter_renameat2"},
	"trace_unlinkat":      {"syscalls", "sys_enter_unlinkat"},
}

func init() {
	if !utils.IsRoot() {
		logger.Log.Error("you need root privileges to run this program")
		os.Exit(1)
	}
}

// Run runs the tracer
// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target=$GOARCH  -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../../bpf/sensor.network.bpf.c -- -I $BPF_HEADERS
func Run(cmd cobra.Command) error {
	var bundleFS = bundle.Bundle

	// Determine tracer mode
	var tracerMode = cmd.Flag("mode").Value.String()
	if tracerMode == "" {
		return errors.New("[mode] flag is required")
	}

	if tracerMode != domain.TracerModeMonitor && tracerMode != domain.TracerModeTrace {
		return fmt.Errorf("[mode] flag is invalid: %s", tracerMode)
	}

	// Load configuration from all sources (YAML files, directories, CLI flags)
	rulesFile, _ := cmd.Flags().GetString("rules-file")
	rulesDir, _ := cmd.Flags().GetString("rules-dir")

	var dataObj []byte
	var cmddata *domain.Data
	var externalRegoFiles []string
	var webhookConfigs []config.WebhookConfig
	var policyCfg *config.PolicyConfig

	if rulesFile != "" || rulesDir != "" {
		// New config system: load from YAML + directory + CLI flags
		cliFlags := gatherCLIFlags(&cmd)
		var regoFiles []string
		var err error
		policyCfg, regoFiles, err = config.LoadAll(rulesFile, rulesDir, cliFlags)
		if err != nil {
			return fmt.Errorf("config loading error: %w", err)
		}

		// Override mode from config if CLI didn't set it explicitly
		if policyCfg.Mode != "" {
			tracerMode = policyCfg.Mode
		}

		dataBytes, data, err := config.ToOPAData(policyCfg)
		if err != nil {
			return fmt.Errorf("config conversion error: %w", err)
		}
		dataObj = dataBytes
		cmddata = data
		externalRegoFiles = regoFiles
		webhookConfigs = policyCfg.Webhooks
	} else {
		// Legacy: CLI flags only
		data, err := parseFlags(&cmd)
		if err != nil {
			return fmt.Errorf("data json error: %w", err)
		}
		cmddata = data

		obj, err := json.Marshal(cmddata)
		if err != nil {
			return fmt.Errorf("error converting dataobj: %w", err)
		}
		dataObj = obj
	}

	bundlePolicy, err := policy.New(bundleFS, dataObj, policy.WithExternalRego(externalRegoFiles))
	if err != nil {
		return fmt.Errorf("policy init error: %w", err)
	}

	bundlePolicy.AddQuery("data.kntrl.policy")

	// Webhook client setup
	var webhookClient *webhook.Client
	if len(webhookConfigs) > 0 {
		var whConfigs []webhook.Config
		for _, wh := range webhookConfigs {
			whConfigs = append(whConfigs, webhook.Config{
				URL:     wh.URL,
				Headers: wh.Headers,
				Events:  wh.Events,
			})
		}
		webhookClient = webhook.New(whConfigs)
		webhookClient.Start(context.Background())
		logger.Log.Infof("webhook alerting enabled with %d endpoint(s)", len(whConfigs))
	}

	// CI environment detection
	ciMeta := ci.Detect()
	if ciMeta != nil {
		logger.Log.Infof("CI detected: %s (repo=%s branch=%s)", ciMeta.Provider, ciMeta.Repository, ciMeta.Branch)
	}

	// Cloud upload client setup
	var cloudClient *cloud.Client
	apiKey, apiURL := resolveCloudConfig(&cmd, policyCfg, rulesFile, rulesDir)
	if apiKey != "" && apiURL != "" {
		sessionID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
		cloudClient = cloud.New(cloud.Config{APIURL: apiURL, APIKey: apiKey}, ciMeta, sessionID)
		cloudClient.Start(context.Background())
		logger.Log.Infof("cloud upload enabled (session=%s)", sessionID)
	}

	var ebpfClient = ebpfman.New()
	if err := ebpfClient.Load(prog); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	defer ebpfClient.Clean()

	modeMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapMode]
	if modeMap == nil {
		return fmt.Errorf("eBPF map %q not found", domain.EBPFCollectionMapMode)
	}
	switch tracerMode {
	case domain.TracerModeTrace:
		if err := modeMap.Put(uint32(0), uint32(domain.TracerModeIndexTrace)); err != nil {
			return fmt.Errorf("failed to set mode: %w", err)
		}

	case domain.TracerModeMonitor:
		if err := modeMap.Put(uint32(0), uint32(domain.TracerModeIndexMonitor)); err != nil {
			return fmt.Errorf("failed to set mode: %w", err)
		}

	default:
		return fmt.Errorf("invalid mode: %s", tracerMode)
	}

	allowedIPMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapAllowedIP]
	if allowedIPMap == nil {
		return fmt.Errorf("eBPF map %q not found", domain.EBPFCollectionMapAllowedIP)
	}
	err = updateAllowedIPMaps(allowedIPMap, cmddata)
	if err != nil {
		return fmt.Errorf("failed to update allow ip map: %w", err)
	}

	allowedHostMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapAllowedHost]
	if allowedHostMap == nil {
		return fmt.Errorf("eBPF map %q not found", domain.EBPFCollectionMapAllowedHost)
	}
	err = updateAllowedHostMap(allowedHostMap, cmddata)
	if err != nil {
		return fmt.Errorf("failed to update allow host map: %w", err)
	}

	// Create ring buffer reader for IPv4 events
	ipv4EventMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapIPV4Events]
	ipV4Events, err := ringbuf.NewReader(ipv4EventMap)
	if err != nil {
		return fmt.Errorf("failed to create ringbuf reader for ipv4 events: %w", err)
	}

	// IPv6 map population and ring buffer
	allowedIPv6Map := ebpfClient.Collection.Maps[domain.EBPFCollectionMapAllowedIPv6]
	if allowedIPv6Map != nil {
		if err := updateAllowedIPv6Maps(allowedIPv6Map, cmddata); err != nil {
			logger.Log.Warnf("failed to update allowed IPv6 map: %v", err)
		}
	}

	var ipv6Events *ringbuf.Reader
	ipv6EventMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapIPV6Events]
	if ipv6EventMap != nil {
		ipv6Events, err = ringbuf.NewReader(ipv6EventMap)
		if err != nil {
			logger.Log.Warnf("failed to create ringbuf reader for ipv6 events: %v", err)
		}
	}

	// Process monitoring setup
	monitorProcesses := true
	if cfg, ok := getProcessConfig(&cmd); ok {
		monitorProcesses = cfg
	}

	var processEvents *ringbuf.Reader
	if monitorProcesses {
		processMonitorMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapProcessMonitor]
		if processMonitorMap != nil {
			if err := processMonitorMap.Put(uint32(0), uint32(1)); err != nil {
				logger.Log.Warnf("failed to enable process monitor: %v", err)
			}
		}

		processEventMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapProcessEvents]
		if processEventMap != nil {
			processEvents, err = ringbuf.NewReader(processEventMap)
			if err != nil {
				logger.Log.Warnf("failed to create ringbuf reader for process events: %v", err)
			}
		}
	}

	// File monitoring setup
	var fileEvents *ringbuf.Reader
	fileMonitorEnabled := false
	var monitoredPaths []string
	var monitoredEnvVars []string
	if rulesFile != "" || rulesDir != "" {
		cliFlags := gatherCLIFlags(&cmd)
		policyCfg, _, _ := config.LoadAll(rulesFile, rulesDir, cliFlags)
		if policyCfg != nil {
			// Enabled by default when rules file exists, unless explicitly disabled
			fileMonitorEnabled = true
			if policyCfg.Rules.File.Enabled != nil && !*policyCfg.Rules.File.Enabled {
				fileMonitorEnabled = false
			}
			monitoredPaths = policyCfg.Rules.File.MonitoredPaths
			monitoredEnvVars = policyCfg.Rules.File.MonitoredEnvVars
		}
	}

	if len(monitoredEnvVars) > 0 {
		// Auto-monitor /proc/*/environ when env var monitoring is configured
		hasEnvironPath := false
		for _, p := range monitoredPaths {
			if strings.Contains(p, "/environ") {
				hasEnvironPath = true
				break
			}
		}
		if !hasEnvironPath {
			monitoredPaths = append(monitoredPaths, "/proc/self/environ")
		}
	}

	if fileMonitorEnabled {
		fileMonitorMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapFileMonitor]
		if fileMonitorMap != nil {
			if err := fileMonitorMap.Put(uint32(0), uint32(1)); err != nil {
				logger.Log.Warnf("failed to enable file monitor: %v", err)
			}
		}

		fileEventMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapFileEvents]
		if fileEventMap != nil {
			fileEvents, err = ringbuf.NewReader(fileEventMap)
			if err != nil {
				logger.Log.Warnf("failed to create ringbuf reader for file events: %v", err)
			}
		}
	}

	// DNS monitoring setup
	var dnsEvents *ringbuf.Reader
	dnsEventMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapDNSEvents]
	if dnsEventMap != nil {
		dnsEvents, err = ringbuf.NewReader(dnsEventMap)
		if err != nil {
			logger.Log.Warnf("failed to create ringbuf reader for dns events: %v", err)
		}
	}

	// Populate allowed DNS servers map
	allowedDNSServersMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapAllowedDNSServers]
	if allowedDNSServersMap != nil && cmddata.AllowedDNSServers != nil {
		for _, ip := range cmddata.AllowedDNSServers {
			ipv4 := ip.To4()
			if ipv4 == nil {
				continue
			}
			ipUint32 := binary.LittleEndian.Uint32(ipv4)
			if err := allowedDNSServersMap.Put(ipUint32, uint32(1)); err != nil {
				logger.Log.Warnf("failed to update allowed DNS server: %v", err)
			}
		}
	}

	// Populate self TGID so BPF programs can drop kntrl's own events
	selfTGIDMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapSelfTGID]
	if selfTGIDMap != nil {
		if err := selfTGIDMap.Put(uint32(0), uint32(os.Getpid())); err != nil {
			logger.Log.Warnf("failed to set self TGID: %v", err)
		}
	}

	// Populate blocked exec map for BPF-level process blocking
	blockedExecMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapBlockedExec]
	if blockedExecMap != nil && cmddata.BlockedExecutables != nil {
		for _, exe := range cmddata.BlockedExecutables {
			var key [16]byte
			copy(key[:], exe)
			if err := blockedExecMap.Put(key, uint32(1)); err != nil {
				logger.Log.Warnf("failed to update blocked exec map: %v", err)
			}
		}
	}

	// Populate protected paths map for BPF-level file write protection
	protectedPathsMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapProtectedPaths]
	if protectedPathsMap != nil && cmddata.ProtectedPaths != nil {
		for _, path := range cmddata.ProtectedPaths {
			var key [256]byte
			copy(key[:], path)
			if err := protectedPathsMap.Put(key, uint32(1)); err != nil {
				logger.Log.Warnf("failed to update protected paths map: %v", err)
			}
		}
	}

	// Preload established TCP connections so existing sessions (e.g. SSH) survive BPF attach
	preloadEstablishedConns(allowedIPMap, allowedIPv6Map)

	// Remove memory lock restrictions for eBPF programs
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// Loop and link eBPF programs
	for name, spec := range ebpfClient.Spec.Programs {
		prg := ebpfClient.Collection.Programs[name]
		logger.Log.WithFields(
			logrus.Fields{
				"name":    name,
				"program": prg,
			}).Debug("loaded program(s):")

		switch spec.Type {
		case ebpf.Kprobe:
			logger.Log.Infof("linking Kprobe [%s]", utils.ParseProgramName(prg))
			l, err := link.Kprobe(spec.AttachTo, prg, nil)
			if err != nil {
				return err
			}
			defer l.Close()

		case ebpf.Tracing:
			logger.Log.Infof("linking tracing [%s]", utils.ParseProgramName(prg))
			l, err := link.AttachTracing(link.TracingOptions{
				Program: prg,
			})
			if err != nil {
				return err
			}
			defer l.Close()

		case ebpf.TracePoint:
			logger.Log.Infof("linking tracepoint [%s]", utils.ParseProgramName(prg))
			tp, ok := tracePointAttach[name]
			if !ok {
				logger.Log.Warnf("unknown tracepoint program: %s", name)
				continue
			}
			l, err := link.Tracepoint(tp[0], tp[1], prg, nil)
			if err != nil {
				return err
			}
			defer l.Close()

		case ebpf.CGroupSKB:
			logger.Log.Infof("linking CGroupSKB [%s]", utils.ParseProgramName(prg))
			cgroup, err := os.Open(rootCgroup)
			if err != nil {
				return err
			}
			l, err := link.AttachCgroup(link.CgroupOptions{
				Path:    cgroup.Name(),
				Attach:  ebpf.AttachCGroupInetEgress,
				Program: prg,
			})
			if err != nil {
				return err
			}
			defer l.Close()
			defer cgroup.Close()

		default:
			logger.Log.Warnf("ebpf program unrecognized: %v", prg)
		}
	}

	// Atomic policy pointer for lock-free reads and SIGHUP reload
	var policyPtr atomic.Pointer[policy.Policy]
	policyPtr.Store(bundlePolicy)

	stopChan := make(chan os.Signal, 1)
	sighupChan := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	signal.Notify(sighupChan, syscall.SIGHUP)

	// SIGHUP handler: reload config and policy
	go func() {
		for range sighupChan {
			logger.Log.Info("SIGHUP: reloading policy...")
			newPolicy, newData, err := loadConfig(rulesFile, rulesDir, gatherCLIFlags(&cmd), bundleFS, externalRegoFiles)
			if err != nil {
				logger.Log.Errorf("SIGHUP reload failed: %v", err)
				continue
			}
			if err := updateAllowedIPMaps(allowedIPMap, newData); err != nil {
				logger.Log.Errorf("SIGHUP: failed to update IP maps: %v", err)
			}
			if err := updateAllowedHostMap(allowedHostMap, newData); err != nil {
				logger.Log.Errorf("SIGHUP: failed to update host maps: %v", err)
			}
			if allowedIPv6Map != nil {
				if err := updateAllowedIPv6Maps(allowedIPv6Map, newData); err != nil {
					logger.Log.Errorf("SIGHUP: failed to update IPv6 maps: %v", err)
				}
			}
			// Reload blocked exec map
			if blockedExecMap != nil && newData.BlockedExecutables != nil {
				for _, exe := range newData.BlockedExecutables {
					var key [16]byte
					copy(key[:], exe)
					if err := blockedExecMap.Put(key, uint32(1)); err != nil {
						logger.Log.Warnf("SIGHUP: failed to update blocked exec map: %v", err)
					}
				}
			}
			// Reload protected paths map
			if protectedPathsMap != nil && newData.ProtectedPaths != nil {
				for _, path := range newData.ProtectedPaths {
					var key [256]byte
					copy(key[:], path)
					if err := protectedPathsMap.Put(key, uint32(1)); err != nil {
						logger.Log.Warnf("SIGHUP: failed to update protected paths map: %v", err)
					}
				}
			}
			cmddata = newData
			policyPtr.Store(newPolicy)
			newPolicy.FlushCache()
			logger.Log.Info("SIGHUP: policy reloaded successfully")
		}
	}()

	// Shutdown signal handler
	go func() {
		<-stopChan
		done <- true

		if err := ipV4Events.Close(); err != nil {
			logger.Log.Warnf("closing ipv4 ringbuf reader: %s", err)
		}
		if ipv6Events != nil {
			if err := ipv6Events.Close(); err != nil {
				logger.Log.Warnf("closing ipv6 ringbuf reader: %s", err)
			}
		}
		if processEvents != nil {
			if err := processEvents.Close(); err != nil {
				logger.Log.Warnf("closing process ringbuf reader: %s", err)
			}
		}
		if dnsEvents != nil {
			if err := dnsEvents.Close(); err != nil {
				logger.Log.Warnf("closing dns ringbuf reader: %s", err)
			}
		}
		if fileEvents != nil {
			if err := fileEvents.Close(); err != nil {
				logger.Log.Warnf("closing file ringbuf reader: %s", err)
			}
		}
	}()

	var outputDir = cmd.Flag("output-file-name").Value.String()

	report := reporter.NewReporter(outputDir)
	if report.Err != nil {
		logger.Log.Fatalf("failed to create reporter: %s", report.Err)
	}
	report.SetSelfPID(uint32(os.Getpid()))

	procTree := proctree.New()

	// Start async DNS resolution worker
	utils.StartDNSWorker()

	// Process event goroutine
	if processEvents != nil {
		go func() {
			for {
				record, err := processEvents.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					logger.Log.Errorf("failed to read process ringbuf event: %v", err)
					continue
				}

				var event domain.ProcessEvent
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
					logger.Log.Debugf("failed to parse process event: %v", err)
					continue
				}

				eventTypeStr := "fork"
				if event.EventType == domain.ProcessEventTypeExec {
					eventTypeStr = "exec"
				}

				// Convert NUL-separated argv to space-separated string.
				// Use ArgsLen from BPF to exclude environment variables.
				argEnd := int(event.ArgsLen)
				if argEnd > len(event.Args) {
					argEnd = len(event.Args)
				}
				argsBytes := bytes.TrimRight(event.Args[:argEnd], "\x00")
				argsStr := strings.ReplaceAll(string(argsBytes), "\x00", " ")

				reportEvent := domain.ProcessReportEvent{
					ProcessID:   event.Pid,
					ParentPID:   event.PPid,
					EventType:   eventTypeStr,
					Comm:        utils.TrimNullBytes(event.Comm),
					Filename:    trimNullBytesLong(event.Filename[:]),
					Args:        argsStr,
					TimestampUs: event.TsUs,
				}

				procTree.Update(event.Pid, event.PPid, reportEvent.Comm)

				// Process blocking logic
				if event.EventType == domain.ProcessEventTypeExec {
					reportEvent.Ancestors = procTree.GetAncestors(event.Pid, 32)

					if event.Blocked == 1 {
						// Already killed by BPF
						reportEvent.Policy = domain.EventPolicyStatusBlock
						logger.Log.Warnf("[process:block:bpf] pid=%d comm=%s KILLED", event.Pid, reportEvent.Comm)
					} else if tracerMode == domain.TracerModeTrace && isAncestryBlocked(reportEvent.Comm, reportEvent.Ancestors, cmddata.BlockedProcessChains) {
						// Ancestry-based block: kill from userspace
						syscall.Kill(int(event.Pid), syscall.SIGKILL)
						reportEvent.Policy = domain.EventPolicyStatusBlock
						logger.Log.Warnf("[process:block:ancestry] pid=%d comm=%s ancestors=%v KILLED", event.Pid, reportEvent.Comm, reportEvent.Ancestors)
					}
				}

				report.WriteProcessEvent(reportEvent)
				if cloudClient != nil {
					cloudClient.Send("process", int64(event.TsUs), reportEvent)
				}

				// Webhook alerting for blocked process events
				if webhookClient != nil && reportEvent.Policy == domain.EventPolicyStatusBlock {
					webhookClient.Send(webhook.Event{
						Type:      "process_block",
						Timestamp: int64(event.TsUs),
						Data:      reportEvent,
					})
				}

				if reportEvent.Policy != domain.EventPolicyStatusBlock {
					logger.Log.Infof("[process] %s pid=%d ppid=%d comm=%s file=%s args=%q",
						eventTypeStr, event.Pid, event.PPid, reportEvent.Comm, reportEvent.Filename, reportEvent.Args)
				}

				// Primary env var detection: scan at exec time
				if eventTypeStr == "exec" && len(monitoredEnvVars) > 0 {
					if vars := utils.FindMatchingEnvVars(event.Pid, monitoredEnvVars); len(vars) > 0 {
						report.WriteFileEvent(domain.FileReportEvent{
							ProcessID:      event.Pid,
							Comm:           utils.TrimNullBytes(event.Comm),
							Filename:       "[inherited]",
							TimestampUs:    event.TsUs,
							Policy:         "flag",
							MatchedEnvVars: vars,
						})
						logger.Log.Infof("[env] pid=%d comm=%s inherited env vars: %v",
							event.Pid, reportEvent.Comm, vars)
					}
				}
			}
		}()
	}

	// SNI event goroutine
	var sniEvents *ringbuf.Reader
	sniEventMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapSNIEvents]
	if sniEventMap != nil {
		sniEvents, err = ringbuf.NewReader(sniEventMap)
		if err != nil {
			logger.Log.Warnf("failed to create ringbuf reader for sni events: %v", err)
		} else {
			defer sniEvents.Close()
			go func() {
				for {
					record, err := sniEvents.Read()
					if err != nil {
						if errors.Is(err, ringbuf.ErrClosed) {
							return
						}
						logger.Log.Errorf("failed to read sni ringbuf event: %v", err)
						continue
					}

					var event domain.SNIEvent
					if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
						logger.Log.Debugf("failed to parse sni event: %v", err)
						continue
					}

					sni := trimNullBytesLong(event.SNI[:])
					logger.Log.Infof("[sni] pid=%d dst=%s:%d sni=%s",
						event.Pid, utils.IntToIP(event.Daddr), event.Dport, sni)
				}
			}()
		}
	}

	// File event goroutine
	if fileEvents != nil {
		go func() {
			hasPathFilter := len(monitoredPaths) > 0
			for {
				record, err := fileEvents.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					logger.Log.Errorf("failed to read file ringbuf event: %v", err)
					continue
				}

				var event domain.FileEvent
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
					logger.Log.Debugf("failed to parse file event: %v", err)
					continue
				}

				comm := utils.TrimNullBytes(event.Comm)
				if comm == progName {
					continue
				}

				filename := trimNullBytesLong(event.Filename[:])

				// Map operation type
				var opStr string
				switch event.Op {
				case domain.FileOpRename:
					opStr = "rename"
				case domain.FileOpUnlink:
					opStr = "unlink"
				default:
					opStr = "open"
				}

				// Blocked events always pass through; non-blocked need path filter
				isFileBlocked := event.Blocked == 1
				if !isFileBlocked {
					// Path filtering: drop events not matching any monitored path
					isEnvFile := len(monitoredEnvVars) > 0 && utils.IsEnvironFile(filename)
					var matched bool
					if hasPathFilter {
						matched, _ = utils.MatchesMonitoredPath(filename, monitoredPaths)
					}
					if !matched && !isEnvFile {
						continue // Drop: doesn't match any monitored path or env pattern
					}
				}

				reportEvent := domain.FileReportEvent{
					ProcessID:   event.Pid,
					Comm:        comm,
					Filename:    filename,
					Flags:       event.Flags,
					TimestampUs: event.TsUs,
					Policy:      "flag",
					Operation:   opStr,
				}

				if isFileBlocked {
					reportEvent.Policy = domain.EventPolicyStatusBlock
					reportEvent.Blocked = true
					logger.Log.Warnf("[file:block:bpf] pid=%d comm=%s file=%s op=%s KILLED",
						event.Pid, comm, filename, opStr)
				}

				// Env var detection for /proc/*/environ accesses
				isEnvFile2 := len(monitoredEnvVars) > 0 && utils.IsEnvironFile(filename)
				if isEnvFile2 {
					if vars := utils.FindMatchingEnvVars(event.Pid, monitoredEnvVars); len(vars) > 0 {
						reportEvent.MatchedEnvVars = vars
					}
				}

				report.WriteFileEvent(reportEvent)
				if cloudClient != nil {
					cloudClient.Send("file", int64(event.TsUs), reportEvent)
				}

				// Webhook: send flagged/blocked file events
				if webhookClient != nil {
					eventType := "file_flag"
					if isFileBlocked {
						eventType = "file_block"
					}
					webhookClient.Send(webhook.Event{
						Type:      eventType,
						Timestamp: int64(event.TsUs),
						Data:      reportEvent,
					})
				}

				if !isFileBlocked {
					logger.Log.Infof("[file] pid=%d comm=%s file=%s op=%s policy=flag%s",
						event.Pid, comm, filename, opStr, fmtEnvVars(reportEvent.MatchedEnvVars))
				}
			}
		}()
	}

	// DNS event goroutine
	if dnsEvents != nil {
		go func() {
			// Dedup: skip repeated events for the same domain within a short window
			dnsDedup := make(map[string]time.Time)
			const dnsDedupTTL = 2 * time.Second

			for {
				record, err := dnsEvents.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					logger.Log.Errorf("failed to read dns ringbuf event: %v", err)
					continue
				}

				var event domain.DNSEvent
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
					logger.Log.Debugf("failed to parse dns event: %v", err)
					continue
				}

				qname := strings.TrimPrefix(trimNullBytesLong(event.Qname[:]), ".")

				// Skip reverse DNS and internal lookups — only forward queries matter for security
				if strings.Contains(qname, "in-addr.arpa") ||
					strings.Contains(qname, "ip6.arpa") ||
					strings.HasSuffix(qname, ".internal") ||
					qname == "" {
					continue
				}

				// Deduplicate: skip if same domain+direction was seen recently
				now := time.Now()
				isResp := event.IsResponse == 1
				dedupKey := qname + "|q"
				if isResp {
					dedupKey = qname + "|r"
				}
				if lastSeen, ok := dnsDedup[dedupKey]; ok && now.Sub(lastSeen) < dnsDedupTTL {
					continue
				}
				dnsDedup[dedupKey] = now

				reportEvent := domain.DNSReportEvent{
					ProcessID:   event.Pid,
					DNSServer:   utils.IntToIP(event.DNSServerIP).String(),
					QueryDomain: qname,
					QueryType:   event.Qtype,
					IsResponse:  event.IsResponse == 1,
					TimestampUs: event.TsUs,
				}

				// Cache IP→domain mapping synchronously so it's ready before connection events
				if reportEvent.IsResponse && reportEvent.QueryDomain != "" {
					utils.CacheDNSDomainAsync(reportEvent.QueryDomain)
				}

				report.WriteDNSEvent(reportEvent)
				if cloudClient != nil {
					cloudClient.Send("dns", int64(event.TsUs), reportEvent)
				}
				logger.Log.Infof("[dns] pid=%d server=%s domain=%s response=%v",
					event.Pid, reportEvent.DNSServer, reportEvent.QueryDomain, reportEvent.IsResponse)
			}
		}()
	}

	// IPv6 event goroutine
	if ipv6Events != nil {
		go func() {
			for {
				record, err := ipv6Events.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					logger.Log.Errorf("failed to read ipv6 ringbuf event: %v", err)
					continue
				}

				var event domain.IP6Event
				if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
					logger.Log.Debugf("failed to parse ipv6 event: %v", err)
					continue
				}

				domainAddress := utils.BytesToIPv6(event.Daddr)
				domainNames, err := utils.LookupAndTrimCached(domainAddress)
				if err != nil {
					logger.Log.Debugf("failed to lookup ipv6 domain: [%s] %v", domainAddress.String(), err)
					domainNames = append(domainNames, ".")
				}

				taskname := utils.TrimNullBytes(event.Task)
				if exeName := utils.ResolveCommFromExe(event.Pid); exeName != "" {
					taskname = exeName
				}
				if taskname == progName {
					continue
				}

				protocol := utils.GetProtocol(event.Proto)
				var policyStatus = domain.EventPolicyStatusPass

				var reportEvent = domain.ReportEvent{
					ProcessID:          event.Pid,
					TaskName:           taskname,
					Protocol:           protocol,
					DestinationAddress: domainAddress.String(),
					DestinationPort:    event.Dport,
					Domains:            domainNames,
					Policy:             policyStatus,
					Ancestors:          procTree.GetAncestors(event.Pid, 32),
				}

				if tracerMode != domain.TracerModeMonitor {
					result, err := policyPtr.Load().EvalEventCached(context.Background(), reportEvent)
					if err != nil {
						logger.Log.Debugf("ipv6 policy eval failed: %v", err)
						continue
					}
					if result {
						policyStatus = domain.EventPolicyStatusPass
						if allowedIPv6Map != nil {
							var addrKey [16]byte
							copy(addrKey[:], event.Daddr[:])
							if err := allowedIPv6Map.Put(addrKey, uint32(1)); err != nil {
								logger.Log.Warnf("failed to update ipv6 allow list: %v", err)
							}
						}
					} else {
						policyStatus = domain.EventPolicyStatusBlock
					}
					reportEvent.Policy = policyStatus
				}

				report.WriteEvent(reportEvent)
				if cloudClient != nil {
					cloudClient.Send("network", int64(event.TsUs), reportEvent)
				}
				logger.Log.Infof("[%d]%s -> %s:%d (%s) [%s/ipv6]| %s",
					event.Pid, taskname, domainAddress, event.Dport, domainNames, protocol, policyStatus)
			}
		}()
	}

	// Event processing loop
	for {
		record, err := ipV4Events.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				goto EXIT
			}
			logger.Log.Errorf("failed to read ringbuf event: %v", err)
			continue
		}

		var event domain.IP4Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Log.Printf("failed to parse ringbuf event: %v", err)
			continue
		}

		domainAddress := utils.IntToIP(event.Daddr)
		domainNames, err := utils.LookupAndTrimCached(domainAddress)
		if err != nil {
			logger.Log.Debugf("failed to lookup domain: [%s] %v", domainAddress.String(), err)
			domainNames = append(domainNames, ".")
		}

		// Skip DNS traffic (port 53) — already captured by DNS monitor
		if event.Dport == 53 {
			continue
		}

		// Evaluate policy
		var policyStatus = domain.EventPolicyStatusPass
		taskname := utils.TrimNullBytes(event.Task)
		if exeName := utils.ResolveCommFromExe(event.Pid); exeName != "" {
			taskname = exeName
		}
		if taskname == progName {
			continue
		}

		protocol := utils.GetProtocol(event.Proto)

		var reportEvent = domain.ReportEvent{
			ProcessID:          event.Pid,
			TaskName:           taskname,
			Protocol:           protocol,
			DestinationAddress: utils.IntToIP(event.Daddr).String(),
			DestinationPort:    event.Dport,
			Domains:            domainNames,
			Policy:             policyStatus,
			Ancestors:          procTree.GetAncestors(event.Pid, 32),
		}

		// Policy logic
		if tracerMode != domain.TracerModeMonitor {
			result, err := policyPtr.Load().EvalEventCached(context.Background(), reportEvent)
			if err != nil {
				logger.Log.Warnf("policy eval failed (skipping): %v", err)
				continue
			}
			if result {
				policyStatus = domain.EventPolicyStatusPass
				if err := allowedIPMap.Put(event.Daddr, uint32(1)); err != nil {
					logger.Log.Warnf("failed to update allow list (map): %v", err)
				} else {
					logger.Log.Infof("ip [%d] added into allowed list", event.Daddr)
				}

			} else {
				policyStatus = domain.EventPolicyStatusBlock
			}
			reportEvent.Policy = policyStatus
		}

		// Report
		report.WriteEvent(reportEvent)
		if cloudClient != nil {
			cloudClient.Send("network", int64(event.TsUs), reportEvent)
		}

		// Webhook alerting
		if webhookClient != nil {
			webhookClient.Send(webhook.Event{
				Type:      policyStatus,
				Timestamp: int64(event.TsUs),
				Data:      reportEvent,
			})
		}

		logger.Log.Infof("[%d]%s -> %s:%d (%s) [%s]| %s",
			event.Pid,
			taskname,
			utils.IntToIP(event.Daddr),
			event.Dport,
			domainNames,
			protocol,
			policyStatus,
		)
	}

EXIT:
	<-done
	prettyOutput, _ := cmd.Flags().GetBool("pretty")

	report.PrintReportTable()
	report.PrintDNSTable()
	report.PrintProcessTable(prettyOutput)
	report.PrintSensitiveAccessReport()
	report.PrintFileTable()

	if cloudClient != nil {
		summary := cloud.SummaryPayload{
			Mode:          tracerMode,
			NetworkEvents: report.GetEvents(),
			ProcessEvents: report.GetProcessEvents(),
			DNSEvents:     report.GetDNSEvents(),
			FileEvents:    report.GetFileEvents(),
			Counts:        report.GetSummaryCounts(),
		}
		if err := cloudClient.SendSummary(summary); err != nil {
			logger.Log.Errorf("cloud summary upload failed: %v", err)
		} else {
			logger.Log.Info("cloud summary uploaded successfully")
		}
		cloudClient.Close()
	}

	report.Close()
	return nil
}

func gatherCLIFlags(cmd *cobra.Command) config.CLIFlags {
	flags := config.CLIFlags{}

	flags.AllowedHosts, _ = cmd.Flags().GetString("allowed-hosts")
	flags.AllowedIPs, _ = cmd.Flags().GetString("allowed-ips")
	flags.Mode = cmd.Flag("mode").Value.String()
	flags.RulesFile, _ = cmd.Flags().GetString("rules-file")
	flags.RulesDir, _ = cmd.Flags().GetString("rules-dir")
	flags.APIKey, _ = cmd.Flags().GetString("api-key")
	flags.APIURL, _ = cmd.Flags().GetString("api-url")

	if cmd.Flags().Changed("allow-local-ranges") {
		val, _ := cmd.Flags().GetBool("allow-local-ranges")
		flags.AllowLocalRanges = &val
	}
	if cmd.Flags().Changed("allow-github-meta") {
		val, _ := cmd.Flags().GetBool("allow-github-meta")
		flags.AllowGithubMeta = &val
	}
	if cmd.Flags().Changed("allow-metadata") {
		val, _ := cmd.Flags().GetBool("allow-metadata")
		flags.AllowMetadata = &val
	}

	return flags
}

func updateAllowedIPMaps(allowedIPMap *ebpf.Map, arg *domain.Data) error {
	for _, ipstr := range arg.AllowedIPs {
		ip := ipstr.To4()
		if ip == nil || len(ip) < 4 {
			continue
		}
		ipUint32 := binary.LittleEndian.Uint32(ip[:4])
		if err := allowedIPMap.Put(ipUint32, uint32(1)); err != nil {
			return err
		}
	}
	return nil
}

func updateAllowedIPv6Maps(allowedIPv6Map *ebpf.Map, arg *domain.Data) error {
	for _, ip := range arg.AllowedIPv6s {
		if len(ip) != net.IPv6len {
			continue
		}
		var key [16]byte
		copy(key[:], ip)
		if err := allowedIPv6Map.Put(key, uint32(1)); err != nil {
			return err
		}
	}
	return nil
}

func updateAllowedHostMap(allowedHostMap *ebpf.Map, arg *domain.Data) error {
	for _, host := range arg.AllowedHosts {
		var key [256]byte
		copy(key[:], host)
		if err := allowedHostMap.Put(key, uint32(1)); err != nil {
			return err
		}
	}
	return nil
}

func loadConfig(rulesFile, rulesDir string, cliFlags config.CLIFlags, bundleFS fs.FS, externalRegoFiles []string) (*policy.Policy, *domain.Data, error) {
	policyCfg, regoFiles, err := config.LoadAll(rulesFile, rulesDir, cliFlags)
	if err != nil {
		return nil, nil, fmt.Errorf("config loading error: %w", err)
	}

	regoFiles = append(regoFiles, externalRegoFiles...)

	dataBytes, data, err := config.ToOPAData(policyCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("config conversion error: %w", err)
	}

	newPolicy, err := policy.New(bundleFS, dataBytes, policy.WithExternalRego(regoFiles))
	if err != nil {
		return nil, nil, fmt.Errorf("policy init error: %w", err)
	}
	newPolicy.AddQuery("data.kntrl.policy")

	return newPolicy, data, nil
}

func getProcessConfig(cmd *cobra.Command) (bool, bool) {
	monitorProcesses, err := cmd.Flags().GetBool("monitor-processes")
	if err != nil {
		return true, false // default to enabled
	}
	return monitorProcesses, true
}

func trimNullBytesLong(p []byte) string {
	for i, v := range p {
		if v == 0 {
			return string(p[:i])
		}
	}
	return string(p)
}

// preloadEstablishedConns reads /proc/net/tcp and /proc/net/tcp6 to discover
// ESTABLISHED connections and pre-populates the BPF allowed IP maps so that
// existing sessions (e.g. SSH) are not dropped when the egress filter attaches.
func preloadEstablishedConns(allowedIPMap, allowedIPv6Map *ebpf.Map) {
	v4 := preloadTCP4(allowedIPMap)
	var v6 int
	if allowedIPv6Map != nil {
		v6 = preloadTCP6(allowedIPv6Map)
	}
	if v4+v6 > 0 {
		logger.Log.Infof("preloaded %d established connections (IPv4=%d, IPv6=%d)", v4+v6, v4, v6)
	}
}

// preloadTCP4 parses /proc/net/tcp for ESTABLISHED (state 01) connections and
// adds their remote IPv4 addresses to the BPF allowed IP map.
func preloadTCP4(m *ebpf.Map) int {
	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		logger.Log.Debugf("preloadTCP4: %v", err)
		return 0
	}
	defer f.Close()

	var count int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		// Field 3 is the connection state; "01" = TCP_ESTABLISHED
		if fields[3] != "01" {
			continue
		}
		// Field 2 is rem_address in hex "XXXXXXXX:PPPP"
		parts := strings.SplitN(fields[2], ":", 2)
		if len(parts) < 1 || len(parts[0]) != 8 {
			continue
		}
		ipHex, err := strconv.ParseUint(parts[0], 16, 32)
		if err != nil {
			continue
		}
		ipUint32 := uint32(ipHex)
		// Skip 0.0.0.0
		if ipUint32 == 0 {
			continue
		}
		if err := m.Put(ipUint32, uint32(1)); err != nil {
			logger.Log.Debugf("preloadTCP4: put failed: %v", err)
		} else {
			count++
		}
	}
	return count
}

// preloadTCP6 parses /proc/net/tcp6 for ESTABLISHED (state 01) connections and
// adds their remote IPv6 addresses to the BPF allowed IPv6 map.
func preloadTCP6(m *ebpf.Map) int {
	f, err := os.Open("/proc/net/tcp6")
	if err != nil {
		logger.Log.Debugf("preloadTCP6: %v", err)
		return 0
	}
	defer f.Close()

	var count int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 {
			continue
		}
		if fields[3] != "01" {
			continue
		}
		parts := strings.SplitN(fields[2], ":", 2)
		if len(parts) < 1 || len(parts[0]) != 32 {
			continue
		}
		hexStr := parts[0]

		// Parse 32-char hex into [16]byte.
		// /proc/net/tcp6 stores each 4-byte group in host (little-endian) order,
		// so we reverse each group to get network byte order for the BPF map key.
		var addr [16]byte
		for i := 0; i < 4; i++ {
			group := hexStr[i*8 : i*8+8]
			for j := 0; j < 4; j++ {
				b, err := strconv.ParseUint(group[j*2:j*2+2], 16, 8)
				if err != nil {
					break
				}
				// Reverse within each 4-byte group: byte 3-j maps to position i*4+j
				addr[i*4+(3-j)] = byte(b)
			}
		}

		// Skip all-zeros (::)
		allZero := true
		for _, b := range addr {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			continue
		}

		if err := m.Put(addr, uint32(1)); err != nil {
			logger.Log.Debugf("preloadTCP6: put failed: %v", err)
		} else {
			count++
		}
	}
	return count
}

func fmtEnvVars(vars []string) string {
	if len(vars) == 0 {
		return ""
	}
	return " env=[" + strings.Join(vars, ",") + "]"
}

func resolveCloudConfig(cmd *cobra.Command, policyCfg *config.PolicyConfig, rulesFile, rulesDir string) (string, string) {
	if (rulesFile != "" || rulesDir != "") && policyCfg != nil {
		return policyCfg.APIKey, policyCfg.APIURL
	}
	// Legacy mode: CLI flags + env fallback
	key, _ := cmd.Flags().GetString("api-key")
	url, _ := cmd.Flags().GetString("api-url")
	if key == "" {
		key = os.Getenv("KNTRL_API_KEY")
	}
	if url == "" {
		url = os.Getenv("KNTRL_API_URL")
	}
	return key, url
}

func parseFlags(cmd *cobra.Command) (*domain.Data, error) {
	allowedHostsFlag := cmd.Flag("allowed-hosts")
	allowedIPAddrFlag := cmd.Flag("allowed-ips")

	if allowedIPAddrFlag.Value.String() == "" && allowedHostsFlag.Value.String() == "" {
		return nil, errors.New("no allowed hostname or IP addresses provided")
	}

	ghmeta, err := cmd.Flags().GetBool("allow-github-meta")
	if err != nil {
		return nil, err
	}
	localranges, err := cmd.Flags().GetBool("allow-local-ranges")
	if err != nil {
		return nil, err
	}
	allowmeta, err := cmd.Flags().GetBool("allow-metadata")
	if err != nil {
		return nil, err
	}

	return parser.ToDataJson(
		allowedHostsFlag.Value.String(),
		allowedIPAddrFlag.Value.String(),
		ghmeta,
		localranges,
		allowmeta,
	), nil
}

// isAncestryBlocked checks if a process with the given comm and ancestors matches
// any blocked process chain configuration.
func isAncestryBlocked(comm string, ancestors []string, chains []domain.BlockedProcessChain) bool {
	for _, chain := range chains {
		if chain.Process != comm {
			continue
		}
		allFound := true
		for _, required := range chain.Ancestors {
			found := false
			for _, actual := range ancestors {
				if required == actual {
					found = true
					break
				}
			}
			if !found {
				allFound = false
				break
			}
		}
		if allFound {
			return true
		}
	}
	return false
}
