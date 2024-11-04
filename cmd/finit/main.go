package main

import (
	"encoding/gob"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strconv"
	"syscall"
	"time"

	init0 "git.ophivana.moe/security/fortify/cmd/finit/ipc"
	"git.ophivana.moe/security/fortify/internal"
	"git.ophivana.moe/security/fortify/internal/fmsg"
)

const (
	// time to wait for linger processes after death of initial process
	residualProcessTimeout = 5 * time.Second
)

// everything beyond this point runs within pid namespace
// proceed with caution!

func main() {
	// sharing stdout with shim
	// USE WITH CAUTION
	fmsg.SetPrefix("init")

	// setting this prevents ptrace
	if err := internal.PR_SET_DUMPABLE__SUID_DUMP_DISABLE(); err != nil {
		fmsg.Fatalf("cannot set SUID_DUMP_DISABLE: %s", err)
		panic("unreachable")
	}

	if os.Getpid() != 1 {
		fmsg.Fatal("this process must run as pid 1")
		panic("unreachable")
	}

	// re-exec
	if len(os.Args) > 0 && (os.Args[0] != "finit" || len(os.Args) != 1) && path.IsAbs(os.Args[0]) {
		if err := syscall.Exec(os.Args[0], []string{"finit"}, os.Environ()); err != nil {
			fmsg.Println("cannot re-exec self:", err)
			// continue anyway
		}
	}

	// setup pipe fd from environment
	var setup *os.File
	if s, ok := os.LookupEnv(init0.Env); !ok {
		fmsg.Fatal("FORTIFY_INIT not set")
		panic("unreachable")
	} else {
		if fd, err := strconv.Atoi(s); err != nil {
			fmsg.Fatalf("cannot parse %q: %v", s, err)
			panic("unreachable")
		} else {
			setup = os.NewFile(uintptr(fd), "setup")
			if setup == nil {
				fmsg.Fatal("invalid config descriptor")
				panic("unreachable")
			}
		}
	}

	var payload init0.Payload
	if err := gob.NewDecoder(setup).Decode(&payload); err != nil {
		fmsg.Fatal("cannot decode init setup payload:", err)
		panic("unreachable")
	} else {
		fmsg.SetVerbose(payload.Verbose)

		// child does not need to see this
		if err = os.Unsetenv(init0.Env); err != nil {
			fmsg.Printf("cannot unset %s: %v", init0.Env, err)
			// not fatal
		} else {
			fmsg.VPrintln("received configuration")
		}
	}

	// die with parent
	if err := internal.PR_SET_PDEATHSIG__SIGKILL(); err != nil {
		fmsg.Fatalf("prctl(PR_SET_PDEATHSIG, SIGKILL): %v", err)
	}

	cmd := exec.Command(payload.Argv0)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Args = payload.Argv
	cmd.Env = os.Environ()

	// pass wayland fd
	if payload.WL != -1 {
		if f := os.NewFile(uintptr(payload.WL), "wayland"); f != nil {
			cmd.Env = append(cmd.Env, "WAYLAND_SOCKET="+strconv.Itoa(3+len(cmd.ExtraFiles)))
			cmd.ExtraFiles = append(cmd.ExtraFiles, f)
		}
	}

	if err := cmd.Start(); err != nil {
		fmsg.Fatalf("cannot start %q: %v", payload.Argv0, err)
	}
	fmsg.Withhold()

	// close setup pipe as setup is now complete
	if err := setup.Close(); err != nil {
		fmsg.Println("cannot close setup pipe:", err)
		// not fatal
	}

	sig := make(chan os.Signal, 2)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	type winfo struct {
		wpid    int
		wstatus syscall.WaitStatus
	}
	info := make(chan winfo, 1)
	done := make(chan struct{})

	go func() {
		var (
			err     error
			wpid    = -2
			wstatus syscall.WaitStatus
		)

		// keep going until no child process is left
		for wpid != -1 {
			if err != nil {
				break
			}

			if wpid != -2 {
				info <- winfo{wpid, wstatus}
			}

			err = syscall.EINTR
			for errors.Is(err, syscall.EINTR) {
				wpid, err = syscall.Wait4(-1, &wstatus, 0, nil)
			}
		}
		if !errors.Is(err, syscall.ECHILD) {
			fmsg.Println("unexpected wait4 response:", err)
		}

		close(done)
	}()

	// closed after residualProcessTimeout has elapsed after initial process death
	timeout := make(chan struct{})

	r := 2
	for {
		select {
		case s := <-sig:
			fmsg.VPrintln("received", s.String())
			fmsg.Resume() // output could still be withheld at this point, so resume is called
			fmsg.Exit(0)
		case w := <-info:
			if w.wpid == cmd.Process.Pid {
				// initial process exited, output is most likely available again
				fmsg.Resume()

				switch {
				case w.wstatus.Exited():
					r = w.wstatus.ExitStatus()
				case w.wstatus.Signaled():
					r = 128 + int(w.wstatus.Signal())
				default:
					r = 255
				}

				go func() {
					time.Sleep(residualProcessTimeout)
					close(timeout)
				}()
			}
		case <-done:
			fmsg.Exit(r)
		case <-timeout:
			fmsg.Println("timeout exceeded waiting for lingering processes")
			fmsg.Exit(r)
		}
	}
}