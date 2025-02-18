package app

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"git.gensokyo.uk/security/fortify/acl"
	"git.gensokyo.uk/security/fortify/dbus"
	"git.gensokyo.uk/security/fortify/fst"
	"git.gensokyo.uk/security/fortify/internal/fmsg"
	"git.gensokyo.uk/security/fortify/internal/sys"
	"git.gensokyo.uk/security/fortify/system"
	"git.gensokyo.uk/security/fortify/wl"
)

const (
	home  = "HOME"
	shell = "SHELL"

	xdgConfigHome   = "XDG_CONFIG_HOME"
	xdgRuntimeDir   = "XDG_RUNTIME_DIR"
	xdgSessionClass = "XDG_SESSION_CLASS"
	xdgSessionType  = "XDG_SESSION_TYPE"

	term    = "TERM"
	display = "DISPLAY"

	pulseServer = "PULSE_SERVER"
	pulseCookie = "PULSE_COOKIE"

	dbusSessionBusAddress = "DBUS_SESSION_BUS_ADDRESS"
	dbusSystemBusAddress  = "DBUS_SYSTEM_BUS_ADDRESS"
)

var (
	ErrXDisplay = errors.New(display + " unset")

	ErrPulseCookie = errors.New("pulse cookie not present")
	ErrPulseSocket = errors.New("pulse socket not present")
	ErrPulseMode   = errors.New("unexpected pulse socket mode")
)

func (seal *appSeal) setupShares(bus [2]*dbus.Config, os sys.State) error {
	if seal.shared {
		panic("seal shared twice")
	}
	seal.shared = true

	/*
		Tmpdir-based share directory
	*/

	// ensure Share (e.g. `/tmp/fortify.%d`)
	// acl is unnecessary as this directory is world executable
	seal.sys.Ensure(seal.SharePath, 0711)

	// ensure process-specific share (e.g. `/tmp/fortify.%d/%s`)
	// acl is unnecessary as this directory is world executable
	seal.share = path.Join(seal.SharePath, seal.id)
	seal.sys.Ephemeral(system.Process, seal.share, 0711)

	// ensure child tmpdir parent directory (e.g. `/tmp/fortify.%d/tmpdir`)
	targetTmpdirParent := path.Join(seal.SharePath, "tmpdir")
	seal.sys.Ensure(targetTmpdirParent, 0700)
	seal.sys.UpdatePermType(system.User, targetTmpdirParent, acl.Execute)

	// ensure child tmpdir (e.g. `/tmp/fortify.%d/tmpdir/%d`)
	targetTmpdir := path.Join(targetTmpdirParent, seal.user.aid.String())
	seal.sys.Ensure(targetTmpdir, 01700)
	seal.sys.UpdatePermType(system.User, targetTmpdir, acl.Read, acl.Write, acl.Execute)
	seal.container.Bind(targetTmpdir, "/tmp", false, true)

	/*
		XDG runtime directory
	*/

	// mount tmpfs on inner runtime (e.g. `/run/user/%d`)
	seal.container.Tmpfs("/run/user", 1*1024*1024)
	seal.container.Tmpfs(seal.innerRuntimeDir, 8*1024*1024)

	// point to inner runtime path `/run/user/%d`
	seal.container.SetEnv[xdgRuntimeDir] = seal.innerRuntimeDir
	seal.container.SetEnv[xdgSessionClass] = "user"
	seal.container.SetEnv[xdgSessionType] = "tty"

	// ensure RunDir (e.g. `/run/user/%d/fortify`)
	seal.sys.Ensure(seal.RunDirPath, 0700)
	seal.sys.UpdatePermType(system.User, seal.RunDirPath, acl.Execute)

	// ensure runtime directory ACL (e.g. `/run/user/%d`)
	seal.sys.Ensure(seal.RuntimePath, 0700) // ensure this dir in case XDG_RUNTIME_DIR is unset
	seal.sys.UpdatePermType(system.User, seal.RuntimePath, acl.Execute)

	// ensure process-specific share local to XDG_RUNTIME_DIR (e.g. `/run/user/%d/fortify/%s`)
	seal.shareLocal = path.Join(seal.RunDirPath, seal.id)
	seal.sys.Ephemeral(system.Process, seal.shareLocal, 0700)
	seal.sys.UpdatePerm(seal.shareLocal, acl.Execute)

	/*
		Inner passwd database
	*/

	// look up shell
	sh := "/bin/sh"
	if s, ok := os.LookupEnv(shell); ok {
		seal.container.SetEnv[shell] = s
		sh = s
	}

	// bind home directory
	homeDir := "/var/empty"
	if seal.user.home != "" {
		homeDir = seal.user.home
	}
	username := "chronos"
	if seal.user.username != "" {
		username = seal.user.username
	}
	seal.container.Bind(seal.user.data, homeDir, false, true)
	seal.container.Chdir = homeDir
	seal.container.SetEnv["HOME"] = homeDir
	seal.container.SetEnv["USER"] = username

	// generate /etc/passwd and /etc/group
	seal.container.CopyBind("/etc/passwd",
		[]byte(username+":x:"+seal.mapuid.String()+":"+seal.mapuid.String()+":Fortify:"+homeDir+":"+sh+"\n"))
	seal.container.CopyBind("/etc/group",
		[]byte("fortify:x:"+seal.mapuid.String()+":\n"))

	/*
		Display servers
	*/

	// pass $TERM to launcher
	if t, ok := os.LookupEnv(term); ok {
		seal.container.SetEnv[term] = t
	}

	// set up wayland
	if seal.Has(system.EWayland) {
		var socketPath string
		if name, ok := os.LookupEnv(wl.WaylandDisplay); !ok {
			fmsg.Verbose(wl.WaylandDisplay + " is not set, assuming " + wl.FallbackName)
			socketPath = path.Join(seal.RuntimePath, wl.FallbackName)
		} else if !path.IsAbs(name) {
			socketPath = path.Join(seal.RuntimePath, name)
		} else {
			socketPath = name
		}

		innerPath := path.Join(seal.innerRuntimeDir, wl.FallbackName)
		seal.container.SetEnv[wl.WaylandDisplay] = wl.FallbackName

		if !seal.directWayland { // set up security-context-v1
			socketDir := path.Join(seal.SharePath, "wayland")
			outerPath := path.Join(socketDir, seal.id)
			seal.sys.Ensure(socketDir, 0711)
			appID := seal.appID
			if appID == "" {
				// use instance ID in case app id is not set
				appID = "uk.gensokyo.fortify." + seal.id
			}
			seal.sys.Wayland(&seal.bwrapSync, outerPath, socketPath, appID, seal.id)
			seal.container.Bind(outerPath, innerPath)
		} else { // bind mount wayland socket (insecure)
			fmsg.Verbose("direct wayland access, PROCEED WITH CAUTION")
			seal.container.Bind(socketPath, innerPath)

			// ensure Wayland socket ACL (e.g. `/run/user/%d/wayland-%d`)
			seal.sys.UpdatePermType(system.EWayland, socketPath, acl.Read, acl.Write, acl.Execute)
		}
	}

	// set up X11
	if seal.Has(system.EX11) {
		// discover X11 and grant user permission via the `ChangeHosts` command
		if d, ok := os.LookupEnv(display); !ok {
			return fmsg.WrapError(ErrXDisplay,
				"DISPLAY is not set")
		} else {
			seal.sys.ChangeHosts("#" + seal.user.uid.String())
			seal.container.SetEnv[display] = d
			seal.container.Bind("/tmp/.X11-unix", "/tmp/.X11-unix")
		}
	}

	/*
		PulseAudio server and authentication
	*/

	if seal.Has(system.EPulse) {
		// check PulseAudio directory presence (e.g. `/run/user/%d/pulse`)
		pd := path.Join(seal.RuntimePath, "pulse")
		ps := path.Join(pd, "native")
		if _, err := os.Stat(pd); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return fmsg.WrapErrorSuffix(err,
					fmt.Sprintf("cannot access PulseAudio directory %q:", pd))
			}
			return fmsg.WrapError(ErrPulseSocket,
				fmt.Sprintf("PulseAudio directory %q not found", pd))
		}

		// check PulseAudio socket permission (e.g. `/run/user/%d/pulse/native`)
		if s, err := os.Stat(ps); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return fmsg.WrapErrorSuffix(err,
					fmt.Sprintf("cannot access PulseAudio socket %q:", ps))
			}
			return fmsg.WrapError(ErrPulseSocket,
				fmt.Sprintf("PulseAudio directory %q found but socket does not exist", pd))
		} else {
			if m := s.Mode(); m&0o006 != 0o006 {
				return fmsg.WrapError(ErrPulseMode,
					fmt.Sprintf("unexpected permissions on %q:", ps), m)
			}
		}

		// hard link pulse socket into target-executable share
		psi := path.Join(seal.shareLocal, "pulse")
		p := path.Join(seal.innerRuntimeDir, "pulse", "native")
		seal.sys.Link(ps, psi)
		seal.container.Bind(psi, p)
		seal.container.SetEnv[pulseServer] = "unix:" + p

		// publish current user's pulse cookie for target user
		if src, err := discoverPulseCookie(os); err != nil {
			// not fatal
			fmsg.Verbose(strings.TrimSpace(err.(*fmsg.BaseError).Message()))
		} else {
			innerDst := fst.Tmp + "/pulse-cookie"
			seal.container.SetEnv[pulseCookie] = innerDst
			payload := new([]byte)
			seal.container.CopyBindRef(innerDst, &payload)
			seal.sys.CopyFile(payload, src, 256, 256)
		}
	}

	/*
		D-Bus proxy
	*/

	if seal.Has(system.EDBus) {
		// ensure dbus session bus defaults
		if bus[0] == nil {
			bus[0] = dbus.NewConfig(seal.appID, true, true)
		}

		// downstream socket paths
		sessionPath, systemPath := path.Join(seal.share, "bus"), path.Join(seal.share, "system_bus_socket")

		// configure dbus proxy
		if f, err := seal.sys.ProxyDBus(bus[0], bus[1], sessionPath, systemPath); err != nil {
			return err
		} else {
			seal.dbusMsg = f
		}

		// share proxy sockets
		sessionInner := path.Join(seal.innerRuntimeDir, "bus")
		seal.container.SetEnv[dbusSessionBusAddress] = "unix:path=" + sessionInner
		seal.container.Bind(sessionPath, sessionInner)
		seal.sys.UpdatePerm(sessionPath, acl.Read, acl.Write)
		if bus[1] != nil {
			systemInner := "/run/dbus/system_bus_socket"
			seal.container.SetEnv[dbusSystemBusAddress] = "unix:path=" + systemInner
			seal.container.Bind(systemPath, systemInner)
			seal.sys.UpdatePerm(systemPath, acl.Read, acl.Write)
		}
	}

	/*
		Miscellaneous
	*/

	// queue overriding tmpfs at the end of seal.container.Filesystem
	for _, dest := range seal.override {
		seal.container.Tmpfs(dest, 8*1024)
	}

	// mount fortify in sandbox for init
	seal.container.Bind(os.MustExecutable(), path.Join(fst.Tmp, "sbin/fortify"))
	seal.container.Symlink("fortify", path.Join(fst.Tmp, "sbin/init"))

	// append extra perms
	for _, p := range seal.extraPerms {
		if p == nil {
			continue
		}
		if p.ensure {
			seal.sys.Ensure(p.name, 0700)
		}
		seal.sys.UpdatePermType(system.User, p.name, p.perms...)
	}

	return nil
}

// discoverPulseCookie attempts various standard methods to discover the current user's PulseAudio authentication cookie
func discoverPulseCookie(os sys.State) (string, error) {
	if p, ok := os.LookupEnv(pulseCookie); ok {
		return p, nil
	}

	// dotfile $HOME/.pulse-cookie
	if p, ok := os.LookupEnv(home); ok {
		p = path.Join(p, ".pulse-cookie")
		if s, err := os.Stat(p); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return p, fmsg.WrapErrorSuffix(err,
					fmt.Sprintf("cannot access PulseAudio cookie %q:", p))
			}
			// not found, try next method
		} else if !s.IsDir() {
			return p, nil
		}
	}

	// $XDG_CONFIG_HOME/pulse/cookie
	if p, ok := os.LookupEnv(xdgConfigHome); ok {
		p = path.Join(p, "pulse", "cookie")
		if s, err := os.Stat(p); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return p, fmsg.WrapErrorSuffix(err,
					fmt.Sprintf("cannot access PulseAudio cookie %q:", p))
			}
			// not found, try next method
		} else if !s.IsDir() {
			return p, nil
		}
	}

	return "", fmsg.WrapError(ErrPulseCookie,
		fmt.Sprintf("cannot locate PulseAudio cookie (tried $%s, $%s/pulse/cookie, $%s/.pulse-cookie)",
			pulseCookie, xdgConfigHome, home))
}
