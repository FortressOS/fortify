package setuid

import (
	"context"
	"errors"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"git.gensokyo.uk/security/fortify/internal"
	"git.gensokyo.uk/security/fortify/internal/fmsg"
	"git.gensokyo.uk/security/fortify/sandbox"
	"git.gensokyo.uk/security/fortify/sandbox/seccomp"
)

/*
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>

static pid_t f_shim_param_ppid = -1;

// this cannot unblock fmsg since Go code is not async-signal-safe
static void f_shim_sigaction(int sig, siginfo_t *si, void *ucontext) {
  if (sig != SIGCONT || si == NULL) {
    // unreachable
    fprintf(stderr, "sigaction: sa_sigaction got invalid siginfo\n");
    return;
  }

  // monitor requests shim exit
  if (si->si_pid == f_shim_param_ppid)
    exit(254);

  fprintf(stderr, "sigaction: got SIGCONT from process %d\n", si->si_pid);

  // shim orphaned before monitor delivers a signal
  if (getppid() != f_shim_param_ppid)
    exit(3);
}

void f_shim_setup_cont_signal(pid_t ppid) {
  struct sigaction new_action = {0}, old_action = {0};
  if (sigaction(SIGCONT, NULL, &old_action) != 0)
    return;
  if (old_action.sa_handler != SIG_DFL) {
    errno = ENOTRECOVERABLE;
    return;
  }

  new_action.sa_sigaction = f_shim_sigaction;
  if (sigemptyset(&new_action.sa_mask) != 0)
    return;
  new_action.sa_flags = SA_ONSTACK | SA_SIGINFO;

  if (sigaction(SIGCONT, &new_action, NULL) != 0)
    return;

  errno = 0;
  f_shim_param_ppid = ppid;
}
*/
import "C"

const shimEnv = "FORTIFY_SHIM"

type shimParams struct {
	// monitor pid, checked against ppid in signal handler
	Monitor int

	// finalised container params
	Container *sandbox.Params
	// path to outer home directory
	Home string

	// verbosity pass through
	Verbose bool
}

// ShimMain is the main function of the shim process and runs as the unconstrained target user.
func ShimMain() {
	fmsg.Prepare("shim")

	if err := sandbox.SetDumpable(sandbox.SUID_DUMP_DISABLE); err != nil {
		log.Fatalf("cannot set SUID_DUMP_DISABLE: %s", err)
	}

	var (
		params     shimParams
		closeSetup func() error
	)
	if f, err := sandbox.Receive(shimEnv, &params, nil); err != nil {
		if errors.Is(err, sandbox.ErrInvalid) {
			log.Fatal("invalid config descriptor")
		}
		if errors.Is(err, sandbox.ErrNotSet) {
			log.Fatal("FORTIFY_SHIM not set")
		}

		log.Fatalf("cannot receive shim setup params: %v", err)
	} else {
		internal.InstallFmsg(params.Verbose)
		closeSetup = f

		// the Go runtime does not expose siginfo_t so SIGCONT is handled in C to check si_pid
		if _, err = C.f_shim_setup_cont_signal(C.pid_t(params.Monitor)); err != nil {
			log.Fatalf("cannot install SIGCONT handler: %v", err)
		}

		// pdeath_signal delivery is checked as if the dying process called kill(2), see kernel/exit.c
		if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGCONT), 0); errno != 0 {
			log.Fatalf("cannot set parent-death signal: %v", errno)
		}
	}

	if params.Container == nil || params.Container.Ops == nil {
		log.Fatal("invalid container params")
	}

	// close setup socket
	if err := closeSetup(); err != nil {
		log.Printf("cannot close setup pipe: %v", err)
		// not fatal
	}

	// ensure home directory as target user
	if s, err := os.Stat(params.Home); err != nil {
		if os.IsNotExist(err) {
			if err = os.Mkdir(params.Home, 0700); err != nil {
				log.Fatalf("cannot create home directory: %v", err)
			}
		} else {
			log.Fatalf("cannot access home directory: %v", err)
		}

		// home directory is created, proceed
	} else if !s.IsDir() {
		log.Fatalf("path %q is not a directory", params.Home)
	}

	var name string
	if len(params.Container.Args) > 0 {
		name = params.Container.Args[0]
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop() // unreachable
	container := sandbox.New(ctx, name)
	container.Params = *params.Container
	container.Stdin, container.Stdout, container.Stderr = os.Stdin, os.Stdout, os.Stderr
	container.Cancel = func(cmd *exec.Cmd) error { return cmd.Process.Signal(os.Interrupt) }
	container.WaitDelay = 2 * time.Second

	if err := container.Start(); err != nil {
		fmsg.PrintBaseError(err, "cannot start container:")
		os.Exit(1)
	}
	if err := container.Serve(); err != nil {
		fmsg.PrintBaseError(err, "cannot configure container:")
	}

	if err := seccomp.Load(seccomp.PresetCommon); err != nil {
		log.Fatalf("cannot load syscall filter: %v", err)
	}

	if err := container.Wait(); err != nil {
		var exitError *exec.ExitError
		if !errors.As(err, &exitError) {
			if errors.Is(err, context.Canceled) {
				os.Exit(2)
			}
			log.Printf("wait: %v", err)
			os.Exit(127)
		}
		os.Exit(exitError.ExitCode())
	}
}
