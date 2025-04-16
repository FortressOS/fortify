package dbus

import (
	"context"
	"io"
	"os/exec"
	"sync"
	"syscall"

	"git.gensokyo.uk/security/fortify/helper"
)

// ProxyName is the file name or path to the proxy program.
// Overriding ProxyName will only affect Proxy instance created after the change.
var ProxyName = "xdg-dbus-proxy"

// Proxy holds the state of a xdg-dbus-proxy process, and should never be copied.
type Proxy struct {
	helper helper.Helper
	ctx    context.Context

	cancel context.CancelCauseFunc
	cause  func() error

	final      *Final
	output     io.Writer
	useSandbox bool

	name string
	CmdF func(any)

	CommandContext func(ctx context.Context) (cmd *exec.Cmd)
	FilterF        func([]byte) []byte

	mu, pmu sync.RWMutex
}

func (p *Proxy) String() string {
	if p == nil {
		return "(invalid dbus proxy)"
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.helper != nil {
		return p.helper.String()
	}

	return "(unused dbus proxy)"
}

// Final describes the outcome of a proxy configuration.
type Final struct {
	Session, System ProxyPair
	// parsed upstream address
	SessionUpstream, SystemUpstream []AddrEntry
	io.WriterTo
}

// Finalise creates a checked argument writer for [Proxy].
func Finalise(sessionBus, systemBus ProxyPair, session, system *Config) (final *Final, err error) {
	if session == nil && system == nil {
		return nil, syscall.EBADE
	}

	var args []string
	if session != nil {
		args = append(args, session.Args(sessionBus)...)
	}
	if system != nil {
		args = append(args, system.Args(systemBus)...)
	}

	final = &Final{Session: sessionBus, System: systemBus}

	final.WriterTo, err = helper.NewCheckedArgs(args)
	if err != nil {
		return
	}

	if session != nil {
		final.SessionUpstream, err = Parse([]byte(final.Session[0]))
		if err != nil {
			return
		}
	}
	if system != nil {
		final.SystemUpstream, err = Parse([]byte(final.System[0]))
		if err != nil {
			return
		}
	}

	return
}

// New returns a new instance of [Proxy].
func New(ctx context.Context, final *Final, output io.Writer) *Proxy {
	return &Proxy{name: ProxyName, ctx: ctx, final: final, output: output, useSandbox: true}
}
