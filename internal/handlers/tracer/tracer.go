package tracer

import (
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
	"sync/atomic"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/kondukto-io/kntrl/bundle"
	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/config"
	ebpfman "github.com/kondukto-io/kntrl/pkg/ebpf"
	"github.com/kondukto-io/kntrl/pkg/logger"
	"github.com/kondukto-io/kntrl/pkg/parser"
	"github.com/kondukto-io/kntrl/pkg/policy"
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

	if rulesFile != "" || rulesDir != "" {
		// New config system: load from YAML + directory + CLI flags
		cliFlags := gatherCLIFlags(&cmd)
		policyCfg, regoFiles, err := config.LoadAll(rulesFile, rulesDir, cliFlags)
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

	var ebpfClient = ebpfman.New()
	if err := ebpfClient.Load(prog); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	defer ebpfClient.Clean()

	switch tracerMode {
	case domain.TracerModeTrace:
		modeMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapMode]
		if err := modeMap.Put(uint32(0), uint32(domain.TracerModeIndexTrace)); err != nil {
			logger.Log.Fatalf("failed to set mode: %v", err)
		}

	case domain.TracerModeMonitor:
		modeMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapMode]
		if err := modeMap.Put(uint32(0), uint32(domain.TracerModeIndexMonitor)); err != nil {
			logger.Log.Fatalf("failed to set mode: %v", err)
		}

	default:
		return fmt.Errorf("invalid mode: %s", tracerMode)
	}

	allowedIPMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapAllowedIP]
	err = updateAllowedIPMaps(allowedIPMap, cmddata)
	if err != nil {
		logger.Log.Fatalf("failed to update allow ip (map): %v", err)
	}

	allowedHostMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapAllowedHost]
	err = updateAllowedHostMap(allowedHostMap, cmddata)
	if err != nil {
		logger.Log.Fatalf("failed to update allow host (map): %v", err)
	}

	// Create ring buffer reader for IPv4 events
	ipv4EventMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapIPV4Events]
	ipV4Events, err := ringbuf.NewReader(ipv4EventMap)
	if err != nil {
		logger.Log.Fatalf("failed to create ringbuf reader for ipv4 events: %v", err)
	}

	defer ipV4Events.Close()

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
		} else {
			defer ipv6Events.Close()
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
			} else {
				defer processEvents.Close()
			}
		}
	}

	// File monitoring setup
	var fileEvents *ringbuf.Reader
	fileMonitorEnabled := false
	if rulesFile != "" || rulesDir != "" {
		// Check file rules from config (default: disabled)
		cliFlags := gatherCLIFlags(&cmd)
		policyCfg, _, _ := config.LoadAll(rulesFile, rulesDir, cliFlags)
		if policyCfg != nil && policyCfg.Rules.File.Enabled != nil && *policyCfg.Rules.File.Enabled {
			fileMonitorEnabled = true
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
			} else {
				defer fileEvents.Close()
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
		} else {
			defer dnsEvents.Close()
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
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT)
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
			policyPtr.Store(newPolicy)
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

				reportEvent := domain.ProcessReportEvent{
					ProcessID:   event.Pid,
					ParentPID:   event.PPid,
					EventType:   eventTypeStr,
					Comm:        utils.TrimNullBytes(event.Comm),
					Filename:    trimNullBytesLong(event.Filename[:]),
					TimestampUs: event.TsUs,
				}

				report.WriteProcessEvent(reportEvent)
				logger.Log.Infof("[process] %s pid=%d ppid=%d comm=%s file=%s",
					eventTypeStr, event.Pid, event.PPid, reportEvent.Comm, reportEvent.Filename)
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

				reportEvent := domain.FileReportEvent{
					ProcessID:   event.Pid,
					Comm:        utils.TrimNullBytes(event.Comm),
					Filename:    trimNullBytesLong(event.Filename[:]),
					Flags:       event.Flags,
					TimestampUs: event.TsUs,
				}

				report.WriteFileEvent(reportEvent)
				logger.Log.Infof("[file] pid=%d comm=%s file=%s flags=%d",
					event.Pid, reportEvent.Comm, reportEvent.Filename, event.Flags)
			}
		}()
	}

	// DNS event goroutine
	if dnsEvents != nil {
		go func() {
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

				reportEvent := domain.DNSReportEvent{
					ProcessID:   event.Pid,
					DNSServer:   utils.IntToIP(event.DNSServerIP).String(),
					QueryDomain: trimNullBytesLong(event.Qname[:]),
					QueryType:   event.Qtype,
					IsResponse:  event.IsResponse == 1,
					TimestampUs: event.TsUs,
				}

				report.WriteDNSEvent(reportEvent)
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
				domainNames, err := utils.LookupAndTrim(domainAddress)
				if err != nil {
					logger.Log.Debugf("failed to lookup ipv6 domain: [%s] %v", domainAddress.String(), err)
					domainNames = append(domainNames, ".")
				}

				taskname := utils.TrimNullBytes(event.Task)
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
				}

				if tracerMode != domain.TracerModeMonitor {
					result, err := policyPtr.Load().EvalEvent(context.Background(), reportEvent)
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
		domainNames, err := utils.LookupAndTrim(domainAddress)
		if err != nil {
			logger.Log.Debugf("failed to lookup domain: [%s] %v", domainAddress.String(), err)
			domainNames = append(domainNames, ".")
		}

		// Evaluate policy
		var policyStatus = domain.EventPolicyStatusPass
		taskname := utils.TrimNullBytes(event.Task)
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
		}

		// Policy logic
		if tracerMode != domain.TracerModeMonitor {
			result, err := policyPtr.Load().EvalEvent(context.Background(), reportEvent)
			if err != nil {
				logger.Log.Debugf("policy eval failed: %v", err)
				return err
			}
			if result {
				policyStatus = domain.EventPolicyStatusPass
				if err := allowedIPMap.Put(event.Daddr, uint32(1)); err != nil {
					logger.Log.Fatalf("failed to update allow list (map): %v", err)
					return err
				}
				logger.Log.Infof("ip [%d] added into allowed list", event.Daddr)

			} else {
				policyStatus = domain.EventPolicyStatusBlock
			}
			reportEvent.Policy = policyStatus
		}

		// Report
		report.WriteEvent(reportEvent)

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
	report.PrintReportTable()
	report.PrintDNSTable()
	report.PrintProcessTable()
	report.PrintFileTable()
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
		var ipUint32 uint32
		if len(ip) > 16 {
			ipUint32 = binary.LittleEndian.Uint32(ip[12:16])
		} else {
			ipUint32 = binary.LittleEndian.Uint32(ip)
		}
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
	for _, hosts := range arg.AllowedHosts {
		h := binary.LittleEndian.Uint32([]byte(hosts + "\x00"))
		if err := allowedHostMap.Put(h, uint32(1)); err != nil {
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
