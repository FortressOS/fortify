package app

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	shim0 "git.gensokyo.uk/security/fortify/cmd/fshim/ipc"
	"git.gensokyo.uk/security/fortify/cmd/fshim/ipc/shim"
	"git.gensokyo.uk/security/fortify/helper"
	"git.gensokyo.uk/security/fortify/internal/fmsg"
	"git.gensokyo.uk/security/fortify/internal/state"
	"git.gensokyo.uk/security/fortify/internal/system"
)

// Start selects a user switcher and starts shim.
// Note that Wait must be called regardless of error returned by Start.
func (a *app) Start() error {
	a.lock.Lock()
	defer a.lock.Unlock()

	// resolve exec paths
	shimExec := [2]string{helper.BubblewrapName}
	if len(a.seal.command) > 0 {
		shimExec[1] = a.seal.command[0]
	}
	for i, n := range shimExec {
		if len(n) == 0 {
			continue
		}
		if filepath.Base(n) == n {
			if s, err := exec.LookPath(n); err == nil {
				shimExec[i] = s
			} else {
				return fmsg.WrapError(err,
					fmt.Sprintf("executable file %q not found in $PATH", n))
			}
		}
	}

	// construct shim manager
	a.shim = shim.New(
		uint32(a.seal.sys.UID()),
		a.seal.sys.user.as,
		a.seal.sys.user.supp,
		&shim0.Payload{
			Argv:  a.seal.command,
			Exec:  shimExec,
			Bwrap: a.seal.sys.bwrap,
			Home:  a.seal.sys.user.data,

			Verbose: fmsg.Verbose(),
		},
	)

	// startup will go ahead, commit system setup
	if err := a.seal.sys.Commit(); err != nil {
		return err
	}
	a.seal.sys.needRevert = true

	// export sync pipe from sys
	a.seal.sys.bwrap.SetSync(a.seal.sys.Sync())

	if startTime, err := a.shim.Start(); err != nil {
		return err
	} else {
		// shim start and setup success, create process state
		sd := state.State{
			ID:     *a.id,
			PID:    a.shim.Unwrap().Process.Pid,
			Config: a.ct.Unwrap(),
			Time:   *startTime,
		}

		// register process state
		var err0 = new(StateStoreError)
		err0.Inner, err0.DoErr = a.seal.store.Do(a.seal.sys.user.aid, func(c state.Cursor) {
			err0.InnerErr = c.Save(&sd)
		})
		a.seal.sys.saveState = true
		return err0.equiv("cannot save process state:")
	}
}

// StateStoreError is returned for a failed state save
type StateStoreError struct {
	// whether inner function was called
	Inner bool
	// error returned by state.Store Do method
	DoErr error
	// error returned by state.Backend Save method
	InnerErr error
	// any other errors needing to be tracked
	Err error
}

func (e *StateStoreError) equiv(a ...any) error {
	if e.Inner && e.DoErr == nil && e.InnerErr == nil && e.Err == nil {
		return nil
	} else {
		return fmsg.WrapErrorSuffix(e, a...)
	}
}

func (e *StateStoreError) Error() string {
	if e.Inner && e.InnerErr != nil {
		return e.InnerErr.Error()
	}

	if e.DoErr != nil {
		return e.DoErr.Error()
	}

	if e.Err != nil {
		return e.Err.Error()
	}

	return "(nil)"
}

func (e *StateStoreError) Unwrap() (errs []error) {
	errs = make([]error, 0, 3)
	if e.DoErr != nil {
		errs = append(errs, e.DoErr)
	}
	if e.InnerErr != nil {
		errs = append(errs, e.InnerErr)
	}
	if e.Err != nil {
		errs = append(errs, e.Err)
	}
	return
}

type RevertCompoundError interface {
	Error() string
	Unwrap() []error
}

func (a *app) Wait() (int, error) {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.shim == nil {
		fmsg.VPrintln("shim not initialised, skipping cleanup")
		return 1, nil
	}

	var r int

	if cmd := a.shim.Unwrap(); cmd == nil {
		// failure prior to process start
		r = 255
	} else {
		wait := make(chan error, 1)
		go func() { wait <- cmd.Wait() }()

		select {
		// wait for process and resolve exit code
		case err := <-wait:
			if err != nil {
				var exitError *exec.ExitError
				if !errors.As(err, &exitError) {
					// should be unreachable
					a.waitErr = err
				}

				// store non-zero return code
				r = exitError.ExitCode()
			} else {
				r = cmd.ProcessState.ExitCode()
			}
			fmsg.VPrintf("process %d exited with exit code %d", cmd.Process.Pid, r)

		// alternative exit path when kill was unsuccessful
		case err := <-a.shim.WaitFallback():
			r = 255
			if err != nil {
				fmsg.Printf("cannot terminate shim on faulted setup: %v", err)
			} else {
				fmsg.VPrintln("alternative exit path selected")
			}
		}
	}

	// child process exited, resume output
	fmsg.Resume()

	// print queued up dbus messages
	if a.seal.dbusMsg != nil {
		a.seal.dbusMsg(func(msgbuf []string) {
			for _, msg := range msgbuf {
				fmsg.Println(msg)
			}
		})
	}

	// update store and revert app setup transaction
	e := new(StateStoreError)
	e.Inner, e.DoErr = a.seal.store.Do(a.seal.sys.user.aid, func(b state.Cursor) {
		e.InnerErr = func() error {
			// destroy defunct state entry
			if cmd := a.shim.Unwrap(); cmd != nil && a.seal.sys.saveState {
				if err := b.Destroy(*a.id); err != nil {
					return err
				}
			}

			// enablements of remaining launchers
			rt, ec := new(system.Enablements), new(system.Criteria)
			ec.Enablements = new(system.Enablements)
			ec.Set(system.Process)
			if states, err := b.Load(); err != nil {
				return err
			} else {
				if l := len(states); l == 0 {
					// cleanup globals as the final launcher
					fmsg.VPrintln("no other launchers active, will clean up globals")
					ec.Set(system.User)
				} else {
					fmsg.VPrintf("found %d active launchers, cleaning up without globals", l)
				}

				// accumulate capabilities of other launchers
				for i, s := range states {
					if s.Config != nil {
						*rt |= s.Config.Confinement.Enablements
					} else {
						fmsg.Printf("state entry %d does not contain config", i)
					}
				}
			}
			// invert accumulated enablements for cleanup
			for i := system.Enablement(0); i < system.Enablement(system.ELen); i++ {
				if !rt.Has(i) {
					ec.Set(i)
				}
			}
			if fmsg.Verbose() {
				labels := make([]string, 0, system.ELen+1)
				for i := system.Enablement(0); i < system.Enablement(system.ELen+2); i++ {
					if ec.Has(i) {
						labels = append(labels, system.TypeString(i))
					}
				}
				if len(labels) > 0 {
					fmsg.VPrintln("reverting operations labelled", strings.Join(labels, ", "))
				}
			}

			if a.seal.sys.needRevert {
				if err := a.seal.sys.Revert(ec); err != nil {
					return err.(RevertCompoundError)
				}
			}

			return nil
		}()
	})

	e.Err = a.seal.store.Close()
	return r, e.equiv("error returned during cleanup:", e)
}
