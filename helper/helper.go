// Package helper runs external helpers with optional sandboxing.
package helper

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"git.gensokyo.uk/security/fortify/helper/proc"
)

var (
	WaitDelay = 2 * time.Second

	commandContext = exec.CommandContext
)

const (
	// FortifyHelper is set to 1 when args fd is enabled and 0 otherwise.
	FortifyHelper = "FORTIFY_HELPER"
	// FortifyStatus is set to 1 when stat fd is enabled and 0 otherwise.
	FortifyStatus = "FORTIFY_STATUS"
)

type Helper interface {
	// Start starts the helper process.
	Start() error
	// Wait blocks until Helper exits.
	Wait() error

	fmt.Stringer
}

func newHelperFiles(
	ctx context.Context,
	wt io.WriterTo,
	stat bool,
	argF func(argsFd, statFd int) []string,
	extraFiles []*os.File,
) (hl *helperFiles, args []string) {
	hl = new(helperFiles)
	hl.ctx = ctx
	hl.useArgsFd = wt != nil
	hl.useStatFd = stat

	hl.extraFiles = new(proc.ExtraFilesPre)
	for _, f := range extraFiles {
		_, v := hl.extraFiles.Append()
		*v = f
	}

	argsFd := -1
	if hl.useArgsFd {
		f := proc.NewWriterTo(wt)
		argsFd = int(proc.InitFile(f, hl.extraFiles))
		hl.files = append(hl.files, f)
	}

	statFd := -1
	if hl.useStatFd {
		f := proc.NewStat(&hl.stat)
		statFd = int(proc.InitFile(f, hl.extraFiles))
		hl.files = append(hl.files, f)
	}

	args = argF(argsFd, statFd)
	return
}

// helperFiles provides a generic wrapper around helper ipc.
type helperFiles struct {
	// whether argsFd is present
	useArgsFd bool
	// whether statFd is present
	useStatFd bool

	// closes statFd
	stat io.Closer
	// deferred extraFiles fulfillment
	files []proc.File
	// passed through to [proc.Fulfill] and [proc.InitFile]
	extraFiles *proc.ExtraFilesPre

	ctx context.Context
}
