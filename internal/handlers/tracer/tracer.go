package tracer

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/kondukto-io/kntrl/internal/core/domain"
	ebpfman "github.com/kondukto-io/kntrl/pkg/ebpf"
	"github.com/kondukto-io/kntrl/pkg/logger"
	"github.com/kondukto-io/kntrl/pkg/reporter"
	"github.com/kondukto-io/kntrl/pkg/utils"
)

var (
	//go:embed bpf_bpfel_x86.o
	prog []byte
)

const (
	rootCgroup = "/sys/fs/cgroup"
)

// Run runs the tracer
// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target=$GOARCH  -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ../../../bpf/bpf.c -- -I $BPF_HEADERS
func Run(cmd cobra.Command) error {
	var tracerMode = cmd.Flag("mode").Value.String()
	if tracerMode == "" {
		return errors.New("[mode] flag is required")
	}

	if tracerMode != domain.TracerModeMonitor && tracerMode != domain.TracerModeTrace {
		return fmt.Errorf("[mode] flag is invalid: %s", tracerMode)
	}

	var allowedHosts = cmd.Flag("hosts").Value.String()
	if allowedHosts == "" {
		logger.Log.Debugf("no host provided allowed")
	}

	allowedIPS, err := utils.ParseHosts(allowedHosts)
	if err != nil {
		return fmt.Errorf("failed to parse allowed hosts: %w", err)
	}

	if !utils.IsRoot() {
		return errors.New("you need root privileges to run this program")
	}

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

	allowMap := ebpfClient.Collection.Maps[domain.EBPFCollectionMapAllow]

	for _, ip := range allowedIPS {
		// convert the IP bytes to __u32
		ipUint32 := binary.LittleEndian.Uint32(ip)
		if err := allowMap.Put(ipUint32, uint32(1)); err != nil {
			// if err := allowMap.Put(uint32(key), ipUint32); err != nil {
			logger.Log.Fatalf("failed to update allow list (map): %v", err)
		}
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
		domainNames, err := net.LookupAddr(domainAddress.String())
		if err != nil {
			logger.Log.Debugf("failed to lookup domain: [%s] %v", domainAddress.String(), err)
			domainNames = append(domainNames, ".")
		}

		var policyStatus = domain.EventPolicyStatusPass
		if tracerMode != domain.TracerModeMonitor {
			policyStatus = policyCheck(allowMap, allowedIPS, domainNames, event.Daddr)
		}

		taskname := utils.XTrim(event.Task)

		var reportEvent = domain.ReportEvent{
			ProcessID:          event.Pid,
			TaskName:           taskname,
			Protocol:           domain.EventProtocolTCP,
			DestinationAddress: utils.IntToIP(event.Daddr).String(),
			DestinationPort:    event.Dport,
			Domains:            domainNames,
			Policy:             policyStatus,
		}

		report.WriteEvent(reportEvent)

		logger.Log.Infof("[%d]%s -> %s:%d (%s) | %s",
			event.Pid,
			taskname,
			utils.IntToIP(event.Daddr),
			event.Dport,
			domainNames,
			policyStatus,
		)
	}

EXIT:
	<-done
	report.PrintReportTable()
	report.Close()
	return nil
}

func policyCheck(allowMap *ebpf.Map, allowedIPS []net.IP, domainNames []string, destinationAddress uint32) string {
	allowedHostsAddress := []string{".github.com", ".kondukto.io"}

	if isInLocalRange(destinationAddress) {

		var ipUint32 = utils.IntToIP(destinationAddress)
		if err := allowMap.Put(ipUint32, uint32(1)); err != nil {
			logger.Log.Fatalf("failed to update allow list (map): %v", err)
		}
		logger.Log.Infof("ip [%d] in local range", ipUint32)
		return domain.EventPolicyStatusPass
	}

	for _, v := range allowedIPS {
		if v.To4().Equal(utils.IntToIP(destinationAddress)) {
			return domain.EventPolicyStatusPass
		}
	}

	for _, allowedHost := range allowedHostsAddress {
		if utils.OneOfContains(allowedHost, domainNames) {
			var ipUint32 = utils.IntToIP(destinationAddress)

			if err := allowMap.Put(ipUint32, uint32(1)); err != nil {
				logger.Log.Fatalf("failed to update allow list (map): %v", err)
				continue
			}

			logger.Log.Infof("ip [%d] added into allowed list", ipUint32)
			return domain.EventPolicyStatusPass
		}
	}

	return domain.EventPolicyStatusBlock
}

func isInLocalRange(daddr uint32) bool {
	ip := utils.IntToIP(daddr)

	for _, r := range utils.AllowedRanges {
		_, cidr, err := net.ParseCIDR(r)
		if err != nil {
			continue
		}
		if cidr.Contains(ip) == true {
			return true
		}
		continue
	}

	return false
}
