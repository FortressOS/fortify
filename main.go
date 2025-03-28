package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"

	"git.gensokyo.uk/security/fortify/command"
	"git.gensokyo.uk/security/fortify/dbus"
	"git.gensokyo.uk/security/fortify/fst"
	"git.gensokyo.uk/security/fortify/internal"
	"git.gensokyo.uk/security/fortify/internal/app"
	"git.gensokyo.uk/security/fortify/internal/fmsg"
	"git.gensokyo.uk/security/fortify/internal/state"
	"git.gensokyo.uk/security/fortify/internal/sys"
	"git.gensokyo.uk/security/fortify/sandbox"
	"git.gensokyo.uk/security/fortify/system"
)

var (
	errSuccess = errors.New("success")

	//go:embed LICENSE
	license string
)

func init() { fmsg.Prepare("fortify") }

var std sys.State = new(sys.Std)

func main() {
	// early init path, skips root check and duplicate PR_SET_DUMPABLE
	sandbox.TryArgv0(fmsg.Output{}, fmsg.Prepare, internal.InstallFmsg)

	if err := sandbox.SetDumpable(sandbox.SUID_DUMP_DISABLE); err != nil {
		log.Printf("cannot set SUID_DUMP_DISABLE: %s", err)
		// not fatal: this program runs as the privileged user
	}

	if os.Geteuid() == 0 {
		log.Fatal("this program must not run as root")
	}

	buildCommand(os.Stderr).MustParse(os.Args[1:], func(err error) {
		fmsg.Verbosef("command returned %v", err)
		if errors.Is(err, errSuccess) {
			fmsg.BeforeExit()
			os.Exit(0)
		}
	})
	log.Fatal("unreachable")
}

func buildCommand(out io.Writer) command.Command {
	var (
		flagVerbose bool
		flagJSON    bool
	)
	c := command.New(out, log.Printf, "fortify", func([]string) error {
		internal.InstallFmsg(flagVerbose)
		return nil
	}).
		Flag(&flagVerbose, "v", command.BoolFlag(false), "Print debug messages to the console").
		Flag(&flagJSON, "json", command.BoolFlag(false), "Serialise output as JSON when applicable")

	c.Command("shim", command.UsageInternal, func([]string) error { app.ShimMain(); return errSuccess })

	c.Command("app", "Launch app defined by the specified config file", func(args []string) error {
		if len(args) < 1 {
			log.Fatal("app requires at least 1 argument")
		}

		// config extraArgs...
		config := tryPath(args[0])
		config.Args = append(config.Args, args[1:]...)

		runApp(config)
		panic("unreachable")
	})

	{
		var (
			dbusConfigSession string
			dbusConfigSystem  string
			mpris             bool
			dbusVerbose       bool

			fid      string
			aid      int
			groups   command.RepeatableFlag
			homeDir  string
			userName string

			wayland, x11, dBus, pulse bool
		)

		c.NewCommand("run", "Configure and start a permissive default sandbox", func(args []string) error {
			// initialise config from flags
			config := &fst.Config{
				ID:   fid,
				Args: args,
			}

			if aid < 0 || aid > 9999 {
				log.Fatalf("aid %d out of range", aid)
			}

			// resolve home/username from os when flag is unset
			var (
				passwd     *user.User
				passwdOnce sync.Once
				passwdFunc = func() {
					var us string
					if uid, err := std.Uid(aid); err != nil {
						fmsg.PrintBaseError(err, "cannot obtain uid from fsu:")
						os.Exit(1)
					} else {
						us = strconv.Itoa(uid)
					}

					if u, err := user.LookupId(us); err != nil {
						fmsg.Verbosef("cannot look up uid %s", us)
						passwd = &user.User{
							Uid:      us,
							Gid:      us,
							Username: "chronos",
							Name:     "Fortify",
							HomeDir:  "/var/empty",
						}
					} else {
						passwd = u
					}
				}
			)

			if homeDir == "os" {
				passwdOnce.Do(passwdFunc)
				homeDir = passwd.HomeDir
			}

			if userName == "chronos" {
				passwdOnce.Do(passwdFunc)
				userName = passwd.Username
			}

			config.Confinement.AppID = aid
			config.Confinement.Groups = groups
			config.Confinement.Outer = homeDir
			config.Confinement.Username = userName

			if wayland {
				config.Confinement.Enablements |= system.EWayland
			}
			if x11 {
				config.Confinement.Enablements |= system.EX11
			}
			if dBus {
				config.Confinement.Enablements |= system.EDBus
			}
			if pulse {
				config.Confinement.Enablements |= system.EPulse
			}

			// parse D-Bus config file from flags if applicable
			if dBus {
				if dbusConfigSession == "builtin" {
					config.Confinement.SessionBus = dbus.NewConfig(fid, true, mpris)
				} else {
					if conf, err := dbus.NewConfigFromFile(dbusConfigSession); err != nil {
						log.Fatalf("cannot load session bus proxy config from %q: %s", dbusConfigSession, err)
					} else {
						config.Confinement.SessionBus = conf
					}
				}

				// system bus proxy is optional
				if dbusConfigSystem != "nil" {
					if conf, err := dbus.NewConfigFromFile(dbusConfigSystem); err != nil {
						log.Fatalf("cannot load system bus proxy config from %q: %s", dbusConfigSystem, err)
					} else {
						config.Confinement.SystemBus = conf
					}
				}

				// override log from configuration
				if dbusVerbose {
					config.Confinement.SessionBus.Log = true
					config.Confinement.SystemBus.Log = true
				}
			}

			// invoke app
			runApp(config)
			panic("unreachable")
		}).
			Flag(&dbusConfigSession, "dbus-config", command.StringFlag("builtin"),
				"Path to D-Bus proxy config file, or \"builtin\" for defaults").
			Flag(&dbusConfigSystem, "dbus-system", command.StringFlag("nil"),
				"Path to system D-Bus proxy config file, or \"nil\" to disable").
			Flag(&mpris, "mpris", command.BoolFlag(false),
				"Allow owning MPRIS D-Bus path, has no effect if custom config is available").
			Flag(&dbusVerbose, "dbus-log", command.BoolFlag(false),
				"Force logging in the D-Bus proxy").
			Flag(&fid, "id", command.StringFlag(""),
				"App ID, leave empty to disable security context app_id").
			Flag(&aid, "a", command.IntFlag(0),
				"Fortify application ID").
			Flag(nil, "g", &groups,
				"Groups inherited by the app process").
			Flag(&homeDir, "d", command.StringFlag("os"),
				"Application home directory").
			Flag(&userName, "u", command.StringFlag("chronos"),
				"Passwd name within sandbox").
			Flag(&wayland, "wayland", command.BoolFlag(false),
				"Allow Wayland connections").
			Flag(&x11, "X", command.BoolFlag(false),
				"Share X11 socket and allow connection").
			Flag(&dBus, "dbus", command.BoolFlag(false),
				"Proxy D-Bus connection").
			Flag(&pulse, "pulse", command.BoolFlag(false),
				"Share PulseAudio socket and cookie")
	}

	var showFlagShort bool
	c.NewCommand("show", "Show the contents of an app configuration", func(args []string) error {
		switch len(args) {
		case 0: // system
			printShowSystem(os.Stdout, showFlagShort, flagJSON)

		case 1: // instance
			name := args[0]
			config, instance := tryShort(name)
			if config == nil {
				config = tryPath(name)
			}
			printShowInstance(os.Stdout, time.Now().UTC(), instance, config, showFlagShort, flagJSON)

		default:
			log.Fatal("show requires 1 argument")
		}
		return errSuccess
	}).Flag(&showFlagShort, "short", command.BoolFlag(false), "Omit filesystem information")

	var psFlagShort bool
	c.NewCommand("ps", "List active apps and their state", func(args []string) error {
		printPs(os.Stdout, time.Now().UTC(), state.NewMulti(std.Paths().RunDirPath), psFlagShort, flagJSON)
		return errSuccess
	}).Flag(&psFlagShort, "short", command.BoolFlag(false), "Print instance id")

	c.Command("version", "Show fortify version", func(args []string) error {
		fmt.Println(internal.Version())
		return errSuccess
	})

	c.Command("license", "Show full license text", func(args []string) error {
		fmt.Println(license)
		return errSuccess
	})

	c.Command("template", "Produce a config template", func(args []string) error {
		printJSON(os.Stdout, false, fst.Template())
		return errSuccess
	})

	c.Command("help", "Show this help message", func([]string) error {
		c.PrintHelp()
		return errSuccess
	})

	return c
}

func runApp(config *fst.Config) {
	ctx, stop := signal.NotifyContext(context.Background(),
		syscall.SIGINT, syscall.SIGTERM)
	defer stop() // unreachable
	a := app.MustNew(ctx, std)

	rs := new(fst.RunState)
	if sa, err := a.Seal(config); err != nil {
		fmsg.PrintBaseError(err, "cannot seal app:")
		rs.ExitCode = 1
	} else {
		// this updates ExitCode
		app.PrintRunStateErr(rs, sa.Run(rs))
	}
	internal.Exit(rs.ExitCode)
}
