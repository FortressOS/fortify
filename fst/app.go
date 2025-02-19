package fst

import (
	"context"
	"time"
)

type App interface {
	// ID returns a copy of App's unique ID.
	ID() ID
	// Run sets up the system and runs the App.
	Run(ctx context.Context, rs *RunState) error

	Seal(config *Config) error
	String() string
}

// RunState stores the outcome of a call to [App.Run].
type RunState struct {
	// Time is the exact point in time where the process was created.
	// Location must be set to UTC.
	//
	// Time is nil if no process was ever created.
	Time *time.Time
	// ExitCode is the value returned by shim.
	ExitCode int
	// RevertErr is stored by the deferred revert call.
	RevertErr error
	// WaitErr is error returned by the underlying wait syscall.
	WaitErr error
}

// Paths contains environment-dependent paths used by fortify.
type Paths struct {
	// path to shared directory (usually `/tmp/fortify.%d`)
	SharePath string `json:"share_path"`
	// XDG_RUNTIME_DIR value (usually `/run/user/%d`)
	RuntimePath string `json:"runtime_path"`
	// application runtime directory (usually `/run/user/%d/fortify`)
	RunDirPath string `json:"run_dir_path"`
}
