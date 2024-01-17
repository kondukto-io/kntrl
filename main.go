package main

import (
	"net"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/kondukto-io/kntrl/kntrl"
	"github.com/kondukto-io/kntrl/logger"
	"github.com/kondukto-io/kntrl/utils"
)

func main() {
	app := &cli.App{
		Name:  os.Args[0],
		Usage: "Runtime security tool to control and monitor egress/ingress traffic in CI/CD runners",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "mode",
				Value: "monitor",
				Usage: "monitor || allowlist (allow)",
			},
			&cli.StringFlag{
				Name:  "hosts",
				Value: "",
				Usage: "enter ip or hostname (192.168.0.100, example.com, .github.com)",
			},
			&cli.StringFlag{
				Name:  "level",
				Value: "info",
				Usage: "log level",
			},
		},
		Action: func(c *cli.Context) error {
			var ips []net.IP
			var err error
			modeType := uint32(0)

			// initialize logger
			logger.SetLevel(c.String("level"))

			mode := c.String("mode")
			switch mode {
			case "allowlist", "allow":
				ips, err = utils.ParseHosts(c.String("hosts"))
				if err != nil {
					return err
				}
				logger.Log.Warnf("mode=[%s] accepts IPv4 only", mode)
				modeType = uint32(1)

			default:
				logger.Log.Infof("mode=[%s]", mode)
			}

			logger.Log.Debugf("IPs:%v", ips)

			//return kntrl.Run(mode, hosts)
			return kntrl.Run(modeType, ips)
		},
	}

	if err := app.Run(os.Args); err != nil {
		logger.Log.Fatal(err)
	}
}
