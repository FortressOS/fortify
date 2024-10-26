package main

import (
	"flag"
	"fmt"
	"text/tabwriter"

	"git.ophivana.moe/security/fortify/internal/fmsg"
	"git.ophivana.moe/security/fortify/internal/state"
)

var (
	stateActionEarly bool
)

func init() {
	flag.BoolVar(&stateActionEarly, "state", false, "print state information of active launchers")
}

// tryState is called after app initialisation
func tryState() {
	if stateActionEarly {
		var w *tabwriter.Writer
		state.MustPrintLauncherStateSimpleGlobal(&w, os.Paths().RunDirPath)
		if w != nil {
			if err := w.Flush(); err != nil {
				fmsg.Println("cannot format output:", err)
			}
		} else {
			fmt.Println("No information available")
		}

		fmsg.Exit(0)
	}
}
