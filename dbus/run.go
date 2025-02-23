package dbus

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"git.gensokyo.uk/security/fortify/helper"
	"git.gensokyo.uk/security/fortify/helper/bwrap"
	"git.gensokyo.uk/security/fortify/ldd"
)

// Start launches the D-Bus proxy.
func (p *Proxy) Start(ctx context.Context, output io.Writer, sandbox bool) error {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.seal == nil {
		return errors.New("proxy not sealed")
	}

	var (
		h helper.Helper

		argF = func(argsFD, statFD int) []string {
			if statFD == -1 {
				return []string{"--args=" + strconv.Itoa(argsFD)}
			} else {
				return []string{"--args=" + strconv.Itoa(argsFD), "--fd=" + strconv.Itoa(statFD)}
			}
		}
	)

	if !sandbox {
		h = helper.New(p.seal, p.name, argF)
		// xdg-dbus-proxy does not need to inherit the environment
		h.SetEnv(make([]string, 0))
	} else {
		// look up absolute path if name is just a file name
		toolPath := p.name
		if filepath.Base(p.name) == p.name {
			if s, err := exec.LookPath(p.name); err != nil {
				return err
			} else {
				toolPath = s
			}
		}

		// resolve libraries by parsing ldd output
		var proxyDeps []*ldd.Entry
		if toolPath != "/nonexistent-xdg-dbus-proxy" {
			if l, err := ldd.Exec(ctx, toolPath); err != nil {
				return err
			} else {
				proxyDeps = l
			}
		}

		bc := &bwrap.Config{
			Unshare:       nil,
			Hostname:      "fortify-dbus",
			Chdir:         "/",
			Syscall:       &bwrap.SyscallPolicy{DenyDevel: true, Multiarch: true},
			Clearenv:      true,
			NewSession:    true,
			DieWithParent: true,
		}

		// resolve proxy socket directories
		bindTarget := make(map[string]struct{}, 2)
		for _, ps := range []string{p.session[1], p.system[1]} {
			if pd := path.Dir(ps); len(pd) > 0 {
				if pd[0] == '/' {
					bindTarget[pd] = struct{}{}
				}
			}
		}
		for k := range bindTarget {
			bc.Bind(k, k, false, true)
		}

		roBindTarget := make(map[string]struct{}, 2+1+len(proxyDeps))

		// xdb-dbus-proxy bin and dependencies
		roBindTarget[path.Dir(toolPath)] = struct{}{}
		for _, ent := range proxyDeps {
			if path.IsAbs(ent.Path) {
				roBindTarget[path.Dir(ent.Path)] = struct{}{}
			}
			if path.IsAbs(ent.Name) {
				roBindTarget[path.Dir(ent.Name)] = struct{}{}
			}
		}

		// resolve upstream bus directories
		for _, as := range []string{p.session[0], p.system[0]} {
			if len(as) > 0 && strings.HasPrefix(as, "unix:path=/") {
				// leave / intact
				roBindTarget[path.Dir(as[10:])] = struct{}{}
			}
		}

		for k := range roBindTarget {
			bc.Bind(k, k)
		}

		h = helper.MustNewBwrap(bc, toolPath, p.seal, argF, nil, nil)
		p.bwrap = bc
	}

	if output != nil {
		h.Stdout(output).Stderr(output)
	}
	c, cancel := context.WithCancelCause(ctx)
	if err := h.Start(c, true); err != nil {
		cancel(err)
		return err
	}

	p.helper = h
	p.ctx = c
	p.cancel = cancel
	return nil
}

var proxyClosed = errors.New("proxy closed")

// Wait blocks until xdg-dbus-proxy exits and releases resources.
func (p *Proxy) Wait() error {
	p.lock.RLock()
	defer p.lock.RUnlock()

	if p.helper == nil {
		return errors.New("dbus: not started")
	}

	errs := make([]error, 3)

	errs[0] = p.helper.Wait()
	if p.cancel == nil &&
		errors.Is(errs[0], context.Canceled) &&
		errors.Is(context.Cause(p.ctx), proxyClosed) {
		errs[0] = nil
	}

	var exitError *exec.ExitError
	if errors.As(errs[0], &exitError) &&
		exitError != nil &&
		exitError.Exited() &&
		exitError.ExitCode() == -1 {
		// exit due to signal
		errs[0] = nil
	}

	// ensure socket removal so ephemeral directory is empty at revert
	if err := os.Remove(p.session[1]); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs[1] = err
	}
	if p.sysP {
		if err := os.Remove(p.system[1]); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs[2] = err
		}
	}

	return errors.Join(errs...)
}

// Close cancels the context passed to the helper instance attached to xdg-dbus-proxy.
func (p *Proxy) Close() {
	p.lock.Lock()
	defer p.lock.Unlock()

	if p.cancel == nil {
		panic("dbus: not started")
	}
	p.cancel(proxyClosed)
	p.cancel = nil
}
