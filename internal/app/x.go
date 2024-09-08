package app

import (
	"fmt"
	"os"

	"git.ophivana.moe/cat/fortify/internal/state"
	"git.ophivana.moe/cat/fortify/internal/system"
	"git.ophivana.moe/cat/fortify/internal/xcb"
)

const display = "DISPLAY"

func (a *App) ShareX() {
	a.setEnablement(state.EnableX)

	// discovery X11 and grant user permission via the `ChangeHosts` command
	if d, ok := os.LookupEnv(display); !ok {
		if system.V.Verbose {
			fmt.Println("X11: DISPLAY not set, skipping")
		}
	} else {
		// add environment variable for new process
		a.AppendEnv(display, d)

		if system.V.Verbose {
			fmt.Printf("X11: Adding XHost entry SI:localuser:%s to display '%s'\n", a.Username, d)
		}
		if err := xcb.ChangeHosts(xcb.HostModeInsert, xcb.FamilyServerInterpreted, "localuser\x00"+a.Username); err != nil {
			state.Fatal(fmt.Sprintf("Error adding XHost entry to '%s':", d), err)
		} else {
			state.XcbActionComplete()
		}
	}
}