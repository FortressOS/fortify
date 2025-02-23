package app

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"git.gensokyo.uk/security/fortify/fst"
	"git.gensokyo.uk/security/fortify/helper"
	"git.gensokyo.uk/security/fortify/internal/app/shim"
	"git.gensokyo.uk/security/fortify/internal/fmsg"
	"git.gensokyo.uk/security/fortify/internal/state"
	"git.gensokyo.uk/security/fortify/system"
)

const shimSetupTimeout = 5 * time.Second

func (seal *outcome) Run(ctx context.Context, rs *fst.RunState) error {
	if !seal.f.CompareAndSwap(false, true) {
		// run does much more than just starting a process; calling it twice, even if the first call fails, will result
		// in inconsistent state that is impossible to clean up; return here to limit damage and hopefully give the
		// other Run a chance to return
		panic("attempted to run twice")
	}

	if rs == nil {
		panic("invalid state")
	}

	/*
		resolve exec paths
	*/

	shimExec := [2]string{helper.BubblewrapName}
	if len(seal.command) > 0 {
		shimExec[1] = seal.command[0]
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

	/*
		prepare/revert os state
	*/

	if err := seal.sys.Commit(ctx); err != nil {
		return err
	}
	store := state.NewMulti(seal.runDirPath)
	deferredStoreFunc := func(c state.Cursor) error { return nil }
	defer func() {
		var revertErr error
		storeErr := new(StateStoreError)
		storeErr.Inner, storeErr.DoErr = store.Do(seal.user.aid.unwrap(), func(c state.Cursor) {
			revertErr = func() error {
				storeErr.InnerErr = deferredStoreFunc(c)
				if errors.Is(storeErr.InnerErr, os.ErrNotExist) {
					fmsg.Verbose("duplicate state entry destruction")
					storeErr.InnerErr = nil
				}

				/*
					revert app setup transaction
				*/

				rt, ec := new(system.Enablements), new(system.Criteria)
				ec.Enablements = new(system.Enablements)
				ec.Set(system.Process)
				if states, err := c.Load(); err != nil {
					// revert per-process state here to limit damage
					return errors.Join(err, seal.sys.Revert(ec))
				} else {
					if l := len(states); l == 0 {
						fmsg.Verbose("no other launchers active, will clean up globals")
						ec.Set(system.User)
					} else {
						fmsg.Verbosef("found %d active launchers, cleaning up without globals", l)
					}

					// accumulate enablements of remaining launchers
					for i, s := range states {
						if s.Config != nil {
							*rt |= s.Config.Confinement.Enablements
						} else {
							log.Printf("state entry %d does not contain config", i)
						}
					}
				}
				// invert accumulated enablements for cleanup
				for i := system.Enablement(0); i < system.Enablement(system.ELen); i++ {
					if !rt.Has(i) {
						ec.Set(i)
					}
				}
				if fmsg.Load() {
					labels := make([]string, 0, system.ELen+1)
					for i := system.Enablement(0); i < system.Enablement(system.ELen+2); i++ {
						if ec.Has(i) {
							labels = append(labels, system.TypeString(i))
						}
					}
					if len(labels) > 0 {
						fmsg.Verbose("reverting operations type", strings.Join(labels, ", "))
					}
				}

				err := seal.sys.Revert(ec)
				if err != nil {
					err = err.(RevertCompoundError)
				}
				return err
			}()
		})
		storeErr.Err = errors.Join(revertErr, store.Close())
		rs.RevertErr = storeErr.equiv("error returned during cleanup:")
	}()

	/*
		shim process lifecycle
	*/

	waitErr := make(chan error, 1)
	cmd := new(shim.Shim)
	if startTime, err := cmd.Start(
		seal.user.aid.String(),
		seal.user.supp,
		seal.bwrapSync,
	); err != nil {
		return err
	} else {
		// whether/when the fsu process was created
		rs.Time = startTime
	}

	c, cancel := context.WithTimeout(ctx, shimSetupTimeout)
	defer cancel()

	go func() {
		waitErr <- cmd.Unwrap().Wait()
		// cancel shim setup in case shim died before receiving payload
		cancel()
	}()

	if err := cmd.Serve(c, &shim.Payload{
		Argv:  seal.command,
		Exec:  shimExec,
		Bwrap: seal.container,
		Home:  seal.user.data,

		Verbose: fmsg.Load(),
	}); err != nil {
		return err
	}

	// shim accepted setup payload, create process state
	sd := state.State{
		ID:   seal.id.unwrap(),
		PID:  cmd.Unwrap().Process.Pid,
		Time: *rs.Time,
	}
	var earlyStoreErr = new(StateStoreError) // returned after blocking on waitErr
	earlyStoreErr.Inner, earlyStoreErr.DoErr = store.Do(seal.user.aid.unwrap(), func(c state.Cursor) { earlyStoreErr.InnerErr = c.Save(&sd, seal.ct) })
	// destroy defunct state entry
	deferredStoreFunc = func(c state.Cursor) error { return c.Destroy(seal.id.unwrap()) }

	select {
	case err := <-waitErr: // block until fsu/shim returns
		if err != nil {
			var exitError *exec.ExitError
			if !errors.As(err, &exitError) {
				// should be unreachable
				rs.WaitErr = err
			}

			// store non-zero return code
			rs.ExitCode = exitError.ExitCode()
		} else {
			rs.ExitCode = cmd.Unwrap().ProcessState.ExitCode()
		}
		if fmsg.Load() {
			fmsg.Verbosef("process %d exited with exit code %d", cmd.Unwrap().Process.Pid, rs.ExitCode)
		}

	// this is reached when a fault makes an already running shim impossible to continue execution
	// however a kill signal could not be delivered (should actually always happen like that since fsu)
	// the effects of this is similar to the alternative exit path and ensures shim death
	case err := <-cmd.WaitFallback():
		rs.ExitCode = 255
		log.Printf("cannot terminate shim on faulted setup: %v", err)

	// alternative exit path relying on shim behaviour on monitor process exit
	case <-ctx.Done():
		fmsg.Verbose("alternative exit path selected")
	}

	fmsg.Resume()
	if seal.dbusMsg != nil {
		// dump dbus message buffer
		seal.dbusMsg()
	}

	return earlyStoreErr.equiv("cannot save process state:")
}

// StateStoreError is returned for a failed state save
type StateStoreError struct {
	// whether inner function was called
	Inner bool
	// returned by the Do method of [state.Store]
	DoErr error
	// returned by the Save/Destroy method of [state.Cursor]
	InnerErr error
	// stores an arbitrary error
	Err error
}

// save saves exactly one arbitrary error in [StateStoreError].
func (e *StateStoreError) save(err error) {
	if err == nil || e.Err != nil {
		panic("invalid call to save")
	}
	e.Err = err
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

	// equiv nullifies e for values where this is reached
	panic("unreachable")
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

// A RevertCompoundError encapsulates errors returned by
// the Revert method of [system.I].
type RevertCompoundError interface {
	Error() string
	Unwrap() []error
}
