//go:build ebpf && linux

package tracer

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/kondukto-io/kntrl/bundle"
	"github.com/kondukto-io/kntrl/internal/core/domain"
	"github.com/kondukto-io/kntrl/pkg/policy"
)

func networkCollection(t *testing.T) *ebpf.Collection {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(prog))
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		switch name {
		case "egress", "connect4", "connect6", "sendmsg4", "sendmsg6":
		default:
			delete(spec.Programs, name)
		}
	}
	c, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("load network programs: %+v", err)
	}
	t.Cleanup(c.Close)
	if err := c.Maps[domain.EBPFCollectionMapMode].Put(uint32(0), uint32(1)); err != nil {
		t.Fatal(err)
	}
	return c
}

// BPF_PROG_TEST_RUN executes the real egress filter, not a reimplementation.
func TestDNSEgress(t *testing.T) {
	c := networkCollection(t)
	resolvers := c.Maps[domain.EBPFCollectionMapDNSResolvers]
	for _, addr := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
		key := domain.DNSResolverKey{Family: 10}
		ip := net.ParseIP(addr)
		if v4 := ip.To4(); v4 != nil {
			key.Family = 2
			copy(key.Address[:], v4)
		} else {
			copy(key.Address[:], ip.To16())
		}
		if err := resolvers.Put(key, uint32(1)); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name, addr string
		port       uint16
		proto      byte
		want       uint32
	}{
		{"approved UDP4", "1.1.1.1", 53, 17, 1},
		{"approved TCP4", "1.1.1.1", 53, 6, 1},
		{"unapproved UDP4", "9.9.9.9", 53, 17, 0},
		{"unapproved TCP4", "9.9.9.9", 53, 6, 0},
		{"approved UDP6", "2606:4700:4700::1111", 53, 17, 1},
		{"approved TCP6", "2606:4700:4700::1111", 53, 6, 1},
		{"unapproved UDP6", "2001:db8::53", 53, 17, 0},
		{"unapproved TCP6", "2001:db8::53", 53, 6, 0},
		{"IPv4 bytes are not IPv6 permission", "101:101::", 53, 17, 0},
		{"resolver other port", "1.1.1.1", 443, 6, 0},
		{"ordinary IP without socket grant", "192.0.2.1", 443, 6, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, err := c.Programs["egress"].Test(egressPacket(tc.addr, tc.port, tc.proto))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("kernel verdict %d, want %d", got, tc.want)
			}
		})
	}
	if err := clearMap(resolvers); err != nil {
		t.Fatal(err)
	}
	got, _, err := c.Programs["egress"].Test(egressPacket("1.1.1.1", 53, 17))
	if err != nil || got != 0 {
		t.Fatalf("removed DNS grant: verdict=%d err=%v", got, err)
	}
	if err := c.Maps[domain.EBPFCollectionMapMode].Put(uint32(0), uint32(0)); err != nil {
		t.Fatal(err)
	}
	got, _, err = c.Programs["egress"].Test(egressPacket("9.9.9.9", 53, 17))
	if err != nil || got != 1 {
		t.Fatalf("monitor: verdict=%d err=%v", got, err)
	}
}

func egressPacket(addr string, port uint16, proto byte) []byte {
	ip := net.ParseIP(addr)
	headerLen := 40
	etherType := uint16(0x86dd)
	if ip.To4() != nil {
		headerLen = 20
		etherType = 0x0800
	}
	p := make([]byte, 14+headerLen+20)
	binary.BigEndian.PutUint16(p[12:14], etherType)
	h := p[14:]
	if headerLen == 20 {
		h[0] = 0x45
		h[8] = 64
		h[9] = proto
		binary.BigEndian.PutUint16(h[2:4], uint16(len(h)))
		copy(h[12:16], []byte{192, 0, 2, 2})
		copy(h[16:20], ip.To4())
	} else {
		h[0] = 0x60
		h[6] = proto
		h[7] = 64
		binary.BigEndian.PutUint16(h[4:6], 20)
		copy(h[8:24], net.ParseIP("2001:db8::1").To16())
		copy(h[24:40], ip.To16())
	}
	binary.BigEndian.PutUint16(h[headerLen:headerLen+2], 12345)
	binary.BigEndian.PutUint16(h[headerLen+2:headerLen+4], port)
	return p
}

// A child enters an isolated cgroup BEFORE creating its socket. The parent
// listener and agent stay outside it, so the test cannot cut off runner/SSH.
func TestSocketClient(t *testing.T) {
	addr := os.Getenv("KNTRL_TEST_SOCKET")
	if addr == "" {
		return
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		if _, err := conn.Write([]byte(scanner.Text())); err != nil && !errors.Is(err, syscall.EPERM) {
			t.Fatal(err)
		}
	}
}

func startSocketClient(t *testing.T, group, addr string) io.WriteCloser {
	t.Helper()
	fd, err := os.Open(group)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSocketClient$")
	cmd.Env = append(os.Environ(), "KNTRL_TEST_SOCKET="+addr)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { in.Close(); cmd.Process.Kill(); cmd.Wait() })
	return in
}

func TestSocketGrantIsolation(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		testSocketGrantIsolation(t, "udp4", "127.0.0.1:0", "connect4", domain.EBPFCollectionMapIPV4Events)
	})
	t.Run("IPv6", func(t *testing.T) {
		testSocketGrantIsolation(t, "udp6", "[::1]:0", "connect6", domain.EBPFCollectionMapIPV6Events)
	})
}

func testSocketGrantIsolation(t *testing.T, network, address, hook, eventMap string) {
	c := networkCollection(t)
	group, err := os.MkdirTemp("/sys/fs/cgroup", "kntrl-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(group); err != nil {
			t.Error(err)
		}
	})
	connectAttach := ebpf.AttachCGroupInet4Connect
	if network == "udp6" {
		connectAttach = ebpf.AttachCGroupInet6Connect
	}
	for name, attach := range map[string]ebpf.AttachType{"egress": ebpf.AttachCGroupInetEgress, hook: connectAttach} {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: group, Attach: attach, Program: c.Programs[name]})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { l.Close() })
	}
	reader, err := ringbuf.NewReader(c.Maps[eventMap])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close() })
	timer := time.AfterFunc(15*time.Second, func() { reader.Close() })
	defer timer.Stop()
	listener, err := net.ListenPacket(network, address)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	first := startSocketClient(t, group, listener.LocalAddr().String())
	readEvent := func() domain.IP4Event {
		t.Helper()
		record, err := reader.Read()
		if err != nil {
			t.Fatal(err)
		}
		var event domain.IP4Event
		if network == "udp6" {
			var v6 domain.IP6Event
			if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &v6); err != nil {
				t.Fatal(err)
			}
			return domain.IP4Event{Event: v6.Event, Dport: v6.Dport}
		}
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			t.Fatal(err)
		}
		return event
	}
	firstEvent := readEvent()
	p, err := policy.New(bundle.Bundle, []byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	p.AddQuery(fmt.Sprintf("input.pid == %d", firstEvent.Pid))
	var ptr atomic.Pointer[policy.Policy]
	ptr.Store(p)
	rt := &tracerRuntime{connections: c.Maps[domain.EBPFCollectionMapConnections], policyPtr: &ptr, cmddata: &domain.Data{}}
	decide := func(event domain.IP4Event, want bool) {
		t.Helper()
		host, _, err := net.SplitHostPort(listener.LocalAddr().String())
		if err != nil {
			t.Fatal(err)
		}
		report := domain.ReportEvent{ProcessID: event.Pid, DestinationAddress: host, DestinationPort: event.Dport, Protocol: "udp"}
		got, err := rt.evaluateConnection(report, event.Cookie, event.Proto)
		if err != nil || got != want {
			t.Fatalf("policy=%v want=%v err=%v", got, want, err)
		}
	}
	// A grant for another port or protocol on the SAME socket is insufficient.
	wrongPort := firstEvent
	wrongPort.Dport++
	wrongProtocol := firstEvent
	wrongProtocol.Proto = 6
	for _, wrong := range []domain.IP4Event{wrongPort, wrongProtocol} {
		decide(wrong, true)
		if _, err := io.WriteString(first, "wrong-destination\n"); err != nil {
			t.Fatal(err)
		}
		expectNoDatagram(t, listener)
	}
	decide(firstEvent, true)
	if _, err := io.WriteString(first, "allowed\n"); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	listener.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := listener.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "allowed" {
		t.Fatalf("allowed payload: %q %v", buf[:n], err)
	}
	second := startSocketClient(t, group, listener.LocalAddr().String())
	secondEvent := readEvent()
	if secondEvent.Cookie == firstEvent.Cookie || secondEvent.Cookie == 0 {
		t.Fatal("socket cookies are not unique")
	}
	decide(secondEvent, false)
	if _, err := io.WriteString(second, "forbidden\n"); err != nil {
		t.Fatal(err)
	}
	expectNoDatagram(t, listener)
	if err := clearMap(rt.connections); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(first, "revoked\n"); err != nil {
		t.Fatal(err)
	}
	expectNoDatagram(t, listener)
}

func expectNoDatagram(t *testing.T, listener net.PacketConn) {
	t.Helper()
	listener.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := listener.ReadFrom(make([]byte, 64)); err == nil {
		t.Fatal("denied payload reached the listener")
	} else if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatal(err)
	}
}
