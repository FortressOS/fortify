package app

import (
	"fmt"
	"os"
	"path"

	"git.ophivana.moe/cat/fortify/internal/acl"
	"git.ophivana.moe/cat/fortify/internal/state"
	"git.ophivana.moe/cat/fortify/internal/system"
)

const (
	// https://manpages.debian.org/experimental/libwayland-doc/wl_display_connect.3.en.html
	waylandDisplay = "WAYLAND_DISPLAY"
)

func (a *App) ShareWayland() {
	a.setEnablement(state.EnableWayland)

	// ensure Wayland socket ACL (e.g. `/run/user/%d/wayland-%d`)
	if w, ok := os.LookupEnv(waylandDisplay); !ok {
		if system.V.Verbose {
			fmt.Println("Wayland: WAYLAND_DISPLAY not set, skipping")
		}
	} else {
		// add environment variable for new process
		wp := path.Join(system.V.Runtime, w)
		a.AppendEnv(waylandDisplay, wp)
		if err := acl.UpdatePerm(wp, a.UID(), acl.Read, acl.Write, acl.Execute); err != nil {
			state.Fatal(fmt.Sprintf("Error preparing Wayland '%s':", w), err)
		} else {
			state.RegisterRevertPath(wp)
		}
		if system.V.Verbose {
			fmt.Printf("Wayland socket '%s' configured\n", w)
		}
	}
}