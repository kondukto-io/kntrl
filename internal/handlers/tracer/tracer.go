// Package tracer implements the core runtime security tracer for kntrl.
//
// It loads eBPF programs into the kernel, attaches them to tracepoints and
// kprobes, and processes events from multiple ring buffers (network, process,
// DNS, file, SNI). Each event type is handled by a dedicated goroutine that
// reads from its ring buffer, evaluates OPA policies, and reports results.
//
// The tracer supports two modes:
//   - monitor: observe-only, all traffic is allowed
//   - trace:   active enforcement, traffic is blocked/allowed per policy
//
// Configuration can come from CLI flags (legacy) or YAML rule files (new).
// Live policy reload is supported via SIGHUP.
package tracer

import (
	"context"
	_ "embed"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
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
	// rootCgroup is the path to the root cgroup v2 hierarchy used for
	// attaching CGroupSKB eBPF programs to filter egress traffic.
	rootCgroup = "/sys/fs/cgroup"

	// progName is used to identify and skip kntrl's own events in ring
	// buffer processing, preventing self-monitoring feedback loops.
	progName = "kntrl"
)

// tracePointAttach maps eBPF program names to their kernel tracepoint
// group/name pairs. Each entry corresponds to a BPF program in the
// compiled object file that should be attached to the specified tracepoint.
var tracePointAttach = map[string][2]string{
	"inet_sock_set_state": {"sock", "inet_sock_set_state"},
	"trace_exec":          {"sched", "sched_process_exec"},
	"trace_openat":        {"syscalls", "sys_enter_openat"},
	"trace_renameat2":     {"syscalls", "sys_enter_renameat2"},
	"trace_unlinkat":      {"syscalls", "sys_enter_unlinkat"},
	"trace_faccessat":     {"syscalls", "sys_enter_faccessat"},
	"trace_newfstatat":    {"syscalls", "sys_enter_newfstatat"},
}

// tracerRuntime holds the shared runtime state used by all event processing
// goroutines. It acts as a dependency container so that each event handler
// can access policy evaluation, reporting, cloud upload, and webhook alerting
// without requiring global state.
type tracerRuntime struct {
	tracerMode       string
	policyPtr        *atomic.Pointer[policy.Policy]
	report           *reporter.Reporter
	procTree         *proctree.ProcessTree
	cloudClient      *cloud.Client
	webhookClient    *webhook.Client
	cmddata          *domain.Data
	monitoredPaths   []string
	monitoredEnvVars []string

	// allowedIPMap and allowedIPv6Map are eBPF maps that the IPv4/IPv6 event
	// handlers update at runtime when policy evaluation allows a connection.
	allowedIPMap   *ebpf.Map
	allowedIPv6Map *ebpf.Map
}

func init() {
	if !utils.IsRoot() {
		logger.Log.Error("you need root privileges to run this program")
		os.Exit(1)
	}
}

// Run is the main entry point for the tracer. It:
//  1. Loads configuration from CLI flags or YAML rule files
//  2. Initializes the OPA policy engine with the embedded bundle
//  3. Sets up optional integrations (webhooks, cloud upload, CI detection)
//  4. Loads and attaches eBPF programs to kernel hooks
//  5. Spawns event processing goroutines for each event type
//  6. Blocks on the IPv4 event loop until a shutdown signal is received
//  7. Prints summary reports and uploads to cloud if configured
//
// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target=$GOARCH  -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../../bpf/sensor.bpf.c -- -I $BPF_HEADERS
func Run(cmd cobra.Command) error {
	var bundleFS = bundle.Bundle

	// --- Configuration loading ---
	tracerMode, cmddata, dataObj, externalRegoFiles, webhookConfigs, policyCfg, err := loadRunConfig(&cmd)
	if err != nil {
		return err
	}
	rulesFile, _ := cmd.Flags().GetString("rules-file")
	rulesDir, _ := cmd.Flags().GetString("rules-dir")

	// --- Policy engine initialization ---
	bundlePolicy, err := policy.New(bundleFS, dataObj, policy.WithExternalRego(externalRegoFiles))
	if err != nil {
		return fmt.Errorf("policy init error: %w", err)
	}
	bundlePolicy.AddQuery("data.kntrl.policy")

	// --- Optional integrations ---
	webhookClient := initWebhookClient(webhookConfigs)
	ciMeta := ci.Detect()
	if ciMeta != nil {
		logger.Log.Infof("CI detected: %s (repo=%s branch=%s)", ciMeta.Provider, ciMeta.Repository, ciMeta.Branch)
	}
	cloudClient := initCloudClient(&cmd, policyCfg, rulesFile, rulesDir, ciMeta)

	// --- eBPF program loading ---
	var ebpfClient = ebpfman.New()
	if err := ebpfClient.Load(prog); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}
	defer ebpfClient.Clean()

	// --- eBPF map configuration ---
	if err := configureTracerMode(ebpfClient, tracerMode); err != nil {
		return err
	}

	allowedIPMap, err := getRequiredMap(ebpfClient, domain.EBPFCollectionMapAllowedIP)
	if err != nil {
		return err
	}
	if err := updateAllowedIPMaps(allowedIPMap, cmddata); err != nil {
		return fmt.Errorf("failed to update allow ip map: %w", err)
	}

	allowedHostMap, err := getRequiredMap(ebpfClient, domain.EBPFCollectionMapAllowedHost)
	if err != nil {
		return err
	}
	if err := updateAllowedHostMap(allowedHostMap, cmddata); err != nil {
		return fmt.Errorf("failed to update allow host map: %w", err)
	}

	// --- Ring buffer readers ---
	ipV4Events, err := initRingBuf(ebpfClient, domain.EBPFCollectionMapIPV4Events)
	if err != nil {
		return fmt.Errorf("failed to create ringbuf reader for ipv4 events: %w", err)
	}

	allowedIPv6Map := ebpfClient.Collection.Maps[domain.EBPFCollectionMapAllowedIPv6]
	if allowedIPv6Map != nil {
		if err := updateAllowedIPv6Maps(allowedIPv6Map, cmddata); err != nil {
			logger.Log.Warnf("failed to update allowed IPv6 map: %v", err)
		}
	}

	ipv6Events := initOptionalRingBuf(ebpfClient, domain.EBPFCollectionMapIPV6Events)
	processEvents := initProcessMonitor(ebpfClient, &cmd)
	fileEvents, monitoredPaths, monitoredEnvVars := initFileMonitor(ebpfClient, &cmd, rulesFile, rulesDir)
	dnsEvents := initOptionalRingBuf(ebpfClient, domain.EBPFCollectionMapDNSEvents)

	// --- Populate auxiliary eBPF maps ---
	populateDNSServerMap(ebpfClient, cmddata)
	populateSelfTGIDMap(ebpfClient)
	populateBlockedExecMap(ebpfClient, cmddata)
	populateProtectedPathsMap(ebpfClient, cmddata)

	// Preload established TCP connections so existing sessions (e.g. SSH)
	// are not disrupted when the egress BPF filter attaches.
	preloadEstablishedConns(allowedIPMap, allowedIPv6Map)

	// Remove memory lock restrictions for eBPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// --- Attach eBPF programs to kernel hooks ---
	cleanups, err := attachPrograms(ebpfClient)
	if err != nil {
		return err
	}
	defer func() {
		for _, fn := range cleanups {
			fn()
		}
	}()

	// --- Runtime state ---
	var policyPtr atomic.Pointer[policy.Policy]
	policyPtr.Store(bundlePolicy)

	rt := &tracerRuntime{
		tracerMode:       tracerMode,
		policyPtr:        &policyPtr,
		report:           initReporter(&cmd),
		procTree:         proctree.New(),
		cloudClient:      cloudClient,
		webhookClient:    webhookClient,
		cmddata:          cmddata,
		monitoredPaths:   monitoredPaths,
		monitoredEnvVars: monitoredEnvVars,
		allowedIPMap:     allowedIPMap,
		allowedIPv6Map:   allowedIPv6Map,
	}

	// Start async DNS resolution worker for reverse lookups.
	utils.StartDNSWorker()

	// --- Signal handling ---
	stopChan := make(chan os.Signal, 1)
	sighupChan := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	signal.Notify(sighupChan, syscall.SIGHUP)

	// SIGHUP: hot-reload configuration and policy without restarting.
	go handleSIGHUP(sighupChan, &policyPtr, rulesFile, rulesDir, &cmd,
		bundleFS, externalRegoFiles, allowedIPMap, allowedHostMap,
		allowedIPv6Map, ebpfClient, rt)

	// Graceful shutdown: close all ring buffer readers to unblock goroutines.
	go handleShutdown(stopChan, done, ipV4Events, ipv6Events,
		processEvents, dnsEvents, fileEvents)

	// --- Start event processing goroutines ---
	if processEvents != nil {
		go rt.processEventLoop(processEvents)
	}

	sniEvents := initOptionalRingBuf(ebpfClient, domain.EBPFCollectionMapSNIEvents)
	if sniEvents != nil {
		defer sniEvents.Close()
		go rt.sniEventLoop(sniEvents)
	}

	if fileEvents != nil {
		go rt.fileEventLoop(fileEvents)
	}
	if dnsEvents != nil {
		go rt.dnsEventLoop(dnsEvents)
	}
	if ipv6Events != nil {
		go rt.ipv6EventLoop(ipv6Events)
	}

	// --- Main IPv4 event loop (blocks until ring buffer is closed) ---
	rt.ipv4EventLoop(ipV4Events)

	// --- Shutdown and reporting ---
	<-done
	prettyOutput, _ := cmd.Flags().GetBool("pretty")

	rt.report.PrintReportTable()
	rt.report.PrintDNSTable()
	rt.report.PrintProcessTable(prettyOutput)
	rt.report.PrintSensitiveAccessReport()
	rt.report.PrintFileTable()

	if rt.cloudClient != nil {
		summary := cloud.SummaryPayload{
			Mode:          tracerMode,
			NetworkEvents: rt.report.GetEvents(),
			ProcessEvents: rt.report.GetProcessEvents(),
			DNSEvents:     rt.report.GetDNSEvents(),
			FileEvents:    rt.report.GetFileEvents(),
			Counts:        rt.report.GetSummaryCounts(),
		}
		if err := rt.cloudClient.SendSummary(summary); err != nil {
			logger.Log.Errorf("cloud summary upload failed: %v", err)
		} else {
			logger.Log.Info("cloud summary uploaded successfully")
		}
		rt.cloudClient.Close()
	}

	rt.report.Close()
	return nil
}

// configureTracerMode writes the selected mode (trace or monitor) to the eBPF
// mode map so that kernel-side programs can adjust their behavior accordingly.
func configureTracerMode(ebpfClient *ebpfman.EBPF, tracerMode string) error {
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
	return nil
}

// getRequiredMap retrieves a named eBPF map from the collection, returning an
// error if the map is not found. Use this for maps that are mandatory.
func getRequiredMap(ebpfClient *ebpfman.EBPF, name string) (*ebpf.Map, error) {
	m := ebpfClient.Collection.Maps[name]
	if m == nil {
		return nil, fmt.Errorf("eBPF map %q not found", name)
	}
	return m, nil
}

// initRingBuf creates a ring buffer reader for a required eBPF map.
func initRingBuf(ebpfClient *ebpfman.EBPF, mapName string) (*ringbuf.Reader, error) {
	m := ebpfClient.Collection.Maps[mapName]
	return ringbuf.NewReader(m)
}

// initOptionalRingBuf creates a ring buffer reader for an optional eBPF map.
// Returns nil if the map doesn't exist or the reader fails to initialize.
func initOptionalRingBuf(ebpfClient *ebpfman.EBPF, mapName string) *ringbuf.Reader {
	m := ebpfClient.Collection.Maps[mapName]
	if m == nil {
		return nil
	}
	reader, err := ringbuf.NewReader(m)
	if err != nil {
		logger.Log.Warnf("failed to create ringbuf reader for %s: %v", mapName, err)
		return nil
	}
	return reader
}

// initProcessMonitor enables process event monitoring if configured,
// returning a ring buffer reader for process events or nil if disabled.
func initProcessMonitor(ebpfClient *ebpfman.EBPF, cmd *cobra.Command) *ringbuf.Reader {
	monitorProcesses := true
	if cfg, ok := getProcessConfig(cmd); ok {
		monitorProcesses = cfg
	}
	if !monitorProcesses {
		return nil
	}

	// Enable the BPF-side process monitor flag.
	processMonitorMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapProcessMonitor]
	if processMonitorMap != nil {
		if err := processMonitorMap.Put(uint32(0), uint32(1)); err != nil {
			logger.Log.Warnf("failed to enable process monitor: %v", err)
		}
	}

	return initOptionalRingBuf(ebpfClient, domain.EBPFCollectionMapProcessEvents)
}

// initFileMonitor sets up file monitoring based on the rules configuration.
// It returns the ring buffer reader, monitored paths, and monitored env vars.
func initFileMonitor(ebpfClient *ebpfman.EBPF, cmd *cobra.Command, rulesFile, rulesDir string) (*ringbuf.Reader, []string, []string) {
	var monitoredPaths []string
	var monitoredEnvVars []string
	fileMonitorEnabled := false

	if rulesFile != "" || rulesDir != "" {
		cliFlags := gatherCLIFlags(cmd)
		policyCfg, _, _ := config.LoadAll(rulesFile, rulesDir, cliFlags)
		if policyCfg != nil {
			// File monitoring is enabled by default when rules file exists,
			// unless the user explicitly disables it in configuration.
			fileMonitorEnabled = true
			if policyCfg.Rules.File.Enabled != nil && !*policyCfg.Rules.File.Enabled {
				fileMonitorEnabled = false
			}
			monitoredPaths = policyCfg.Rules.File.MonitoredPaths
			monitoredEnvVars = policyCfg.Rules.File.MonitoredEnvVars
		}
	}

	// When monitoring environment variables, automatically add /proc/*/environ
	// to the watch list so BPF captures reads of that pseudo-file.
	if len(monitoredEnvVars) > 0 {
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

	if !fileMonitorEnabled {
		logger.Log.Info("file monitoring disabled")
		return nil, monitoredPaths, monitoredEnvVars
	}

	logger.Log.Infof("file monitoring enabled: %d monitored paths, %d env vars",
		len(monitoredPaths), len(monitoredEnvVars))
	for _, p := range monitoredPaths {
		logger.Log.Infof("  monitored path: %s", p)
	}

	// Enable the BPF-side file monitor flag.
	fileMonitorMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapFileMonitor]
	if fileMonitorMap != nil {
		if err := fileMonitorMap.Put(uint32(0), uint32(1)); err != nil {
			logger.Log.Warnf("failed to enable file monitor: %v", err)
		}
	}

	reader := initOptionalRingBuf(ebpfClient, domain.EBPFCollectionMapFileEvents)
	return reader, monitoredPaths, monitoredEnvVars
}

// initWebhookClient creates a webhook client if webhook configurations are
// provided, starting its background delivery goroutine.
func initWebhookClient(webhookConfigs []config.WebhookConfig) *webhook.Client {
	if len(webhookConfigs) == 0 {
		return nil
	}
	var whConfigs []webhook.Config
	for _, wh := range webhookConfigs {
		whConfigs = append(whConfigs, webhook.Config{
			URL:     wh.URL,
			Headers: wh.Headers,
			Events:  wh.Events,
		})
	}
	client := webhook.New(whConfigs)
	client.Start(context.Background())
	logger.Log.Infof("webhook alerting enabled with %d endpoint(s)", len(whConfigs))
	return client
}

// initCloudClient creates a cloud upload client if API credentials are
// configured, starting its background NATS streaming goroutine.
func initCloudClient(cmd *cobra.Command, policyCfg *config.PolicyConfig, rulesFile, rulesDir string, ciMeta *ci.Metadata) *cloud.Client {
	apiKey, apiURL := resolveCloudConfig(cmd, policyCfg, rulesFile, rulesDir)
	if apiKey == "" || apiURL == "" {
		return nil
	}
	sessionID := fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
	client := cloud.New(cloud.Config{APIURL: apiURL, APIKey: apiKey}, ciMeta, sessionID)
	client.Start(context.Background())
	logger.Log.Infof("cloud upload enabled (session=%s)", sessionID)
	return client
}

// initReporter creates a new event reporter that writes to the output file
// specified by CLI flags.
func initReporter(cmd *cobra.Command) *reporter.Reporter {
	outputDir, _ := cmd.Flags().GetString("output-file-name")
	report := reporter.NewReporter(outputDir)
	if report.Err != nil {
		logger.Log.Fatalf("failed to create reporter: %s", report.Err)
	}
	report.SetSelfPID(uint32(os.Getpid()))
	return report
}

// attachPrograms iterates over all eBPF programs in the loaded collection and
// attaches each one to its appropriate kernel hook (kprobe, tracepoint, tracing,
// or cgroup). Deferred cleanup ensures hooks are detached on shutdown.
func attachPrograms(ebpfClient *ebpfman.EBPF) (cleanups []func(), retErr error) {
	for name, spec := range ebpfClient.Spec.Programs {
		prg := ebpfClient.Collection.Programs[name]
		logger.Log.WithFields(logrus.Fields{
			"name":    name,
			"program": prg,
		}).Debug("loaded program(s):")

		switch spec.Type {
		case ebpf.Kprobe:
			logger.Log.Infof("linking Kprobe [%s]", utils.ParseProgramName(prg))
			l, err := link.Kprobe(spec.AttachTo, prg, nil)
			if err != nil {
				return cleanups, err
			}
			cleanups = append(cleanups, func() { l.Close() })

		case ebpf.Tracing:
			logger.Log.Infof("linking tracing [%s]", utils.ParseProgramName(prg))
			l, err := link.AttachTracing(link.TracingOptions{Program: prg})
			if err != nil {
				return cleanups, err
			}
			cleanups = append(cleanups, func() { l.Close() })

		case ebpf.TracePoint:
			logger.Log.Infof("linking tracepoint [%s]", utils.ParseProgramName(prg))
			tp, ok := tracePointAttach[name]
			if !ok {
				logger.Log.Warnf("unknown tracepoint program: %s", name)
				continue
			}
			l, err := link.Tracepoint(tp[0], tp[1], prg, nil)
			if err != nil {
				return cleanups, err
			}
			cleanups = append(cleanups, func() { l.Close() })

		case ebpf.CGroupSKB:
			logger.Log.Infof("linking CGroupSKB [%s]", utils.ParseProgramName(prg))
			cgroup, err := os.Open(rootCgroup)
			if err != nil {
				return cleanups, err
			}
			l, err := link.AttachCgroup(link.CgroupOptions{
				Path:    cgroup.Name(),
				Attach:  ebpf.AttachCGroupInetEgress,
				Program: prg,
			})
			if err != nil {
				cgroup.Close()
				return cleanups, err
			}
			cleanups = append(cleanups, func() { l.Close(); cgroup.Close() })

		default:
			logger.Log.Warnf("ebpf program unrecognized: %v", prg)
		}
	}
	return cleanups, nil
}

// handleSIGHUP listens for SIGHUP signals and performs a hot-reload of the
// configuration, policy, and eBPF maps. This allows operators to update rules
// without restarting the tracer.
func handleSIGHUP(
	sighupChan chan os.Signal,
	policyPtr *atomic.Pointer[policy.Policy],
	rulesFile, rulesDir string,
	cmd *cobra.Command,
	bundleFS fs.FS,
	externalRegoFiles []string,
	allowedIPMap, allowedHostMap, allowedIPv6Map *ebpf.Map,
	ebpfClient *ebpfman.EBPF,
	rt *tracerRuntime,
) {
	for range sighupChan {
		logger.Log.Info("SIGHUP: reloading policy...")
		newPolicy, newData, err := loadConfig(rulesFile, rulesDir, gatherCLIFlags(cmd), bundleFS, externalRegoFiles)
		if err != nil {
			logger.Log.Errorf("SIGHUP reload failed: %v", err)
			continue
		}

		// Refresh all eBPF maps with the new configuration.
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
		populateBlockedExecMap(ebpfClient, newData)
		populateProtectedPathsMap(ebpfClient, newData)

		rt.cmddata = newData
		policyPtr.Store(newPolicy)
		newPolicy.FlushCache()
		logger.Log.Info("SIGHUP: policy reloaded successfully")
	}
}

// handleShutdown waits for a termination signal and then closes all ring
// buffer readers, unblocking the event processing goroutines so they can
// exit cleanly.
func handleShutdown(stopChan chan os.Signal, done chan bool, readers ...*ringbuf.Reader) {
	<-stopChan
	done <- true
	for _, r := range readers {
		if r != nil {
			if err := r.Close(); err != nil {
				logger.Log.Warnf("closing ringbuf reader: %s", err)
			}
		}
	}
}

