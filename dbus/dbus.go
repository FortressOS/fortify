package dbus

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"

	"git.ophivana.moe/cat/fortify/helper"
)

// Proxy holds references to a xdg-dbus-proxy process, and should never be copied.
// Once sealed, configuration changes will no longer be possible and attempting to do so will result in a panic.
type Proxy struct {
	cmd *exec.Cmd

	statP [2]*os.File
	argsP [2]*os.File

	path    string
	session [2]string
	system  [2]string

	wait  *chan error
	read  *chan error
	ready *chan bool

	seal io.WriterTo
	lock sync.RWMutex
}

func (p *Proxy) String() string {
	if p == nil {
		return "(invalid dbus proxy)"
	}

	p.lock.RLock()
	defer p.lock.RUnlock()

	if p.cmd != nil {
		return p.cmd.String()
	}

	if p.seal != nil {
		return p.seal.(helper.Args).String()
	}

	return "(unsealed dbus proxy)"
}

// Seal seals the Proxy instance.
func (p *Proxy) Seal(session, system *Config) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.seal != nil {
		panic("dbus proxy sealed twice")
	}

	if session == nil && system == nil {
		return errors.New("no configuration to seal")
	}

	seal := helper.NewArgs()

	var args []string
	if session != nil {
		args = append(args, session.Args(p.session)...)
	}
	if system != nil {
		args = append(args, system.Args(p.system)...)
	}
	if err := seal.Seal(args); err != nil {
		return err
	}

	p.seal = seal
	return nil
}

// New returns a reference to a new unsealed Proxy.
func New(binPath string, session, system [2]string) *Proxy {
	return &Proxy{path: binPath, session: session, system: system}
}
