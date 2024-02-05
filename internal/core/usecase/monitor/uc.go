package prevent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/internal/core/port/event"
	"github.com/kondukto-io/kntrl/internal/core/port/worker"
	"github.com/kondukto-io/kntrl/pkg/logger"
	"github.com/kondukto-io/kntrl/pkg/reporter"
	"github.com/kondukto-io/kntrl/pkg/utils"
	"github.com/sirupsen/logrus"
)

type useCase struct {
	eventUC   event.UseCase
	eventRepo event.Repository
}

func New(eventUC event.UseCase, eventRepo event.Repository) worker.UseCase {
	return &useCase{
		eventUC:   eventUC,
		eventRepo: eventRepo,
	}
}

const (
	rootCgroup = "/sys/fs/cgroup"
)

func (u useCase) Prepare(program []byte) error {
	return u.eventRepo.Load(program)
}

func (u useCase) Start(allowedIPS []net.IP, outputDir string, prog []byte) error {
	defer u.eventRepo.Clean()

	if err := u.eventUC.PutModeMap(uint32(0), uint32(domain.ModeIndexMonitor)); err != nil {
		logger.Log.Fatalf("failed to set mode: %v", err)
	}

	for _, ip := range allowedIPS {
		// convert the IP bytes to __u32
		var ipUint32 = binary.LittleEndian.Uint32(ip)
		if err := u.eventUC.PutAllowMap(ipUint32, uint32(1)); err != nil {
			logger.Log.Fatalf("failed to update allow list (map): %v", err)
		}
	}

	ipV4ClosedEvent, err := u.eventRepo.ReadByPerf(domain.EBPFCollectionMapIPV4ClosedEvents)
	if err != nil {
		logger.Log.Fatalf("failed to read ipv4 closed events: %v", err)
	}

	defer ipV4ClosedEvent.Close()

	// allocate memory
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	// loop and link
	for name, spec := range u.eventRepo.GetSpecPrograms() {
		prg := u.eventRepo.GetSingleProgramBySpec(name)
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

	ipV4Events, err := u.eventRepo.ReadByPerf(domain.EBPFCollectionMapIPV4Events)
	if err != nil {
		logger.Log.Fatalf("failed to read ipv4 events: %v", err)
	}

	defer ipV4Events.Close()

	// signal handler
	go func() {
		<-sigs
		done <- true

		if err := ipV4Events.Close(); err != nil {
			logger.Log.Warnf("closing perf reader: %s", err)
		}
	}()

	report := reporter.NewReporter(outputDir)
	if report.Err != nil {
		logger.Log.Fatalf("failed to start reporter: %v", err)
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
