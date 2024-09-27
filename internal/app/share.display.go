package app

import (
	"errors"
	"os"
	"path"

	"git.ophivana.moe/cat/fortify/acl"
	"git.ophivana.moe/cat/fortify/internal/state"
)

const (
	term    = "TERM"
	display = "DISPLAY"

	// https://manpages.debian.org/experimental/libwayland-doc/wl_display_connect.3.en.html
	waylandDisplay = "WAYLAND_DISPLAY"
)

var (
	ErrWayland  = errors.New(waylandDisplay + " unset")
	ErrXDisplay = errors.New(display + " unset")
)

type ErrDisplayEnv BaseError

func (seal *appSeal) shareDisplay() error {
	// pass $TERM to launcher
	if t, ok := os.LookupEnv(term); ok {
		seal.appendEnv(term, t)
	}

	// set up wayland
	if seal.et.Has(state.EnableWayland) {
		if wd, ok := os.LookupEnv(waylandDisplay); !ok {
			return (*ErrDisplayEnv)(wrapError(ErrWayland, "WAYLAND_DISPLAY is not set"))
		} else {
			// wayland socket path
			wp := path.Join(seal.RuntimePath, wd)
			seal.appendEnv(waylandDisplay, wp)

			// ensure Wayland socket ACL (e.g. `/run/user/%d/wayland-%d`)
			seal.sys.updatePerm(wp, acl.Read, acl.Write, acl.Execute)
		}
	}

	// set up X11
	if seal.et.Has(state.EnableX) {
		// discover X11 and grant user permission via the `ChangeHosts` command
		if d, ok := os.LookupEnv(display); !ok {
			return (*ErrDisplayEnv)(wrapError(ErrXDisplay, "DISPLAY is not set"))
		} else {
			seal.sys.changeHosts(seal.sys.Username)
			seal.appendEnv(display, d)
		}
	}

	return nil
}