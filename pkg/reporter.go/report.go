package reporter

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/pterm/pterm"
)

type Reporter struct {
	file   *os.File
	events []e
	Err    error
}

type e struct {
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
func NewReporter() Reporter {
	const filename = "/tmp/kntrl.out"
	var r = Reporter{}

	f, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		r.Err = fmt.Errorf("error open report file: %w", err)
		return r
	}

	r.file = f
	return r
}

//func (r *reporter) Report(event bpfEvent) {
//	daddr := utils.IntToIP(event.Daddr)
//	domain, err := net.LookupAddr(daddr.String())
//	if err != nil {
//		domain = append(domain, ".")
//	}
//
//	ev := e{
//		Pid:    event.Pid,
//		Comm:   utils.XTrim(event.Comm),
//		Proto:  utils.PrintProtocol(event.Proto),
//		Saddr:  utils.IntToIP(event.Saddr),
//		Sport:  event.Sport,
//		Daddr:  daddr,
//		Domain: domain,
//		Dport:  event.Dport,
//		Policy: event.Policy,
//	}
//
//	r.events = append(r.events, ev)
//
//	c, err := json.Marshal(ev)
//	if err != nil {
//		panic(err)
//	}
//	r.file.WriteString(string(c))
//}

func (r *Reporter) Clean() {
	r.file.Close()
}

func (r *Reporter) Print() {
	data := pterm.TableData{
		{"Pid", "Comm", "Proto", "Domain", "Destination Addr", "Policy"},
	}

	for _, v := range r.events {
		res := make([]string, 0)
		res = append(res, strconv.FormatUint(uint64(v.Pid), 10))
		res = append(res, v.Comm)
		res = append(res, v.Proto)
		res = append(res, v.Domain...)
		//res = append(res, v.Daddr.String())
		res = append(res, fmt.Sprintf("%s:%d", v.Daddr.String(), v.Dport))
		res = append(res, strconv.FormatBool(v.Policy))
		data = append(data, res)
	}

	pterm.DefaultTable.WithHasHeader().WithRowSeparator("-").WithHeaderRowSeparator("-").WithData(data).Render()
}

func hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))

	return hex.EncodeToString(hasher.Sum(nil))
}
