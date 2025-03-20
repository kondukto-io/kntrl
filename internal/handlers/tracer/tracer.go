package tracer

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/kondukto-io/kntrl/bundle"
	"github.com/kondukto-io/kntrl/internal/core/domain"
	ebpfman "github.com/kondukto-io/kntrl/pkg/ebpf"
	"github.com/kondukto-io/kntrl/pkg/logger"
	"github.com/kondukto-io/kntrl/pkg/parser"
	"github.com/kondukto-io/kntrl/pkg/policy"
	"github.com/kondukto-io/kntrl/pkg/reporter"
	"github.com/kondukto-io/kntrl/pkg/utils"
)

var (
	//go:embed bpf_bpfel_x86.o
	prog []byte
)

const (
	rootCgroup = "/sys/fs/cgroup"
	progName   = "kntrl"
)

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

	var tracerMode = cmd.Flag("mode").Value.String()
	if tracerMode == "" {
		return errors.New("[mode] flag is required")
	}

	if tracerMode != domain.TracerModeMonitor && tracerMode != domain.TracerModeTrace {
		return fmt.Errorf("[mode] flag is invalid: %s", tracerMode)
	}

	cmddata, err := parseFlags(&cmd)
	if err != nil {
		return fmt.Errorf("data json error: %w", err)
	}

	dataObj, err := json.Marshal(cmddata)
	if err != nil {
		return fmt.Errorf("error converting dataobj: %w", err)
	}

	bundlePolicy, err := policy.New(bundleFS, dataObj)
	if err != nil {
		return fmt.Errorf("policy init error: %w", err)
	}

	bundlePolicy.AddQuery("data.kntrl.policy")

	var ebpfClient = ebpfman.New()
	if err := ebpfClient.Load(prog); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	defer ebpfClient.Clean()

	switch tracerMode {
	case domain.TracerModeTrace:
		// set mode for filtering
		modeMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapMode]
		if err := modeMap.Put(uint32(0), uint32(domain.TracerModeIndexTrace)); err != nil {
			logger.Log.Fatalf("failed to set mode: %v", err)
		}

	case domain.TracerModeMonitor:
		// set mode for filtering
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

	allowedHostMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapAllowedIP]
	err = updateAllowedHostMap(allowedHostMap, cmddata)
	if err != nil {
		logger.Log.Fatalf("failed to update allow host (map): %v", err)
	}

	ipv4EventMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapIPV4Events]
	ipV4Events, err := perf.NewReader(ipv4EventMap, 4096)
	if err != nil {
		logger.Log.Fatalf("failed to read ipv4 events: %v", err)
	}

	defer ipV4Events.Close()

	ipv4ClosedMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapIPV4ClosedEvents]
	ipV4ClosedEvent, err := perf.NewReader(ipv4ClosedMap, 4096)
	if err != nil {
		logger.Log.Fatalf("failed to read ipv4 closed events: %v", err)
	}

	defer ipV4ClosedEvent.Close()

	// allocate memory
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// loop and link
	for name, spec := range ebpfClient.Spec.Programs {
		prg := ebpfClient.Collection.Programs[name]
		logger.Log.WithFields(
			logrus.Fields{
				"name":    name,
				"program": prg,
			}).Debug("loaded program(s):")

		switch spec.Type {
		case ebpf.Kprobe:
			// link Krobe
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
			l, err := link.Tracepoint("sock", "inet_sock_set_state", prg, nil)
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

	sigs := make(chan os.Signal, 1)
	done := make(chan bool, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGKILL, syscall.SIGQUIT, syscall.SIGHUP)

	// signal handler
	go func() {
		<-sigs
		done <- true

		if err := ipV4Events.Close(); err != nil {
			logger.Log.Warnf("closing perf reader: %s", err)
		}
	}()

	var outputDir = cmd.Flag("output-file-name").Value.String()

	report := reporter.NewReporter(outputDir)
	if report.Err != nil {
		logger.Log.Fatalf("failed to read ipv4 closed events: %s", err)
	}

	// IPv4Events
	for {
		record, err := ipV4Events.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				goto EXIT
			}
			logger.Log.Errorf("failed to read perf event: %v", err)
			continue
		}

		var event domain.IP4Event
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Log.Printf("failed to parse perf event: %b", err)
			continue
		}

		domainAddress := utils.IntToIP(event.Daddr)
		domainNames, err := utils.LookupAndTrim(domainAddress)
		if err != nil {
			logger.Log.Debugf("failed to lookup domain: [%s] %v", domainAddress.String(), err)
			domainNames = append(domainNames, ".")
		}

		// evaluate policy
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

		// policy logic
		if tracerMode != domain.TracerModeMonitor {
			result, err := bundlePolicy.EvalEvent(context.Background(), reportEvent)
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

		// report
		report.WriteEvent(reportEvent)

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
	report.Close()
	return nil
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

func updateAllowedHostMap(allowedHostMap *ebpf.Map, arg *domain.Data) error {
	for _, hosts := range arg.AllowedHosts {
		h := binary.LittleEndian.Uint32([]byte(hosts + "\x00"))
		if err := allowedHostMap.Put(h, uint32(1)); err != nil {
			return err
		}
	}
	return nil
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

	return parser.ToDataJson(
		allowedHostsFlag.Value.String(),
		allowedIPAddrFlag.Value.String(),
		ghmeta,
		localranges,
	), nil
}
