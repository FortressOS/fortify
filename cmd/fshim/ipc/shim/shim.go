package shim

import (
	"context"
	"encoding/gob"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	shim0 "git.gensokyo.uk/security/fortify/cmd/fshim/ipc"
	"git.gensokyo.uk/security/fortify/internal"
	"git.gensokyo.uk/security/fortify/internal/fmsg"
	"git.gensokyo.uk/security/fortify/internal/proc"
)

// used by the parent process

type Shim struct {
	// user switcher process
	cmd *exec.Cmd
	// uid of shim target user
	uid uint32
	// string representation of application id
	aid string
	// string representation of supplementary group ids
	supp []string
	// fallback exit notifier with error returned killing the process
	killFallback chan error
	// shim setup payload
	payload *shim0.Payload
	// monitor to shim encoder
	encoder *gob.Encoder
}

func New(uid uint32, aid string, supp []string, payload *shim0.Payload) *Shim {
	return &Shim{uid: uid, aid: aid, supp: supp, payload: payload}
}

func (s *Shim) String() string {
	if s.cmd == nil {
		return "(unused shim manager)"
	}
	return s.cmd.String()
}

func (s *Shim) Unwrap() *exec.Cmd {
	return s.cmd
}

func (s *Shim) WaitFallback() chan error {
	return s.killFallback
}

func (s *Shim) Start() (*time.Time, error) {
	// prepare user switcher invocation
	var fsu string
	if p, ok := internal.Check(internal.Fsu); !ok {
		fmsg.Fatal("invalid fsu path, this copy of fshim is not compiled correctly")
		panic("unreachable")
	} else {
		fsu = p
	}
	s.cmd = exec.Command(fsu)

	// pass shim setup pipe
	if fd, e, err := proc.Setup(&s.cmd.ExtraFiles); err != nil {
		return nil, fmsg.WrapErrorSuffix(err,
			"cannot create shim setup pipe:")
	} else {
		s.encoder = e
		s.cmd.Env = []string{
			shim0.Env + "=" + strconv.Itoa(fd),
			"FORTIFY_APP_ID=" + s.aid,
		}
	}

	// format fsu supplementary groups
	if len(s.supp) > 0 {
		fmsg.VPrintf("attaching supplementary group ids %s", s.supp)
		s.cmd.Env = append(s.cmd.Env, "FORTIFY_GROUPS="+strings.Join(s.supp, " "))
	}
	s.cmd.Stdin, s.cmd.Stdout, s.cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	s.cmd.Dir = "/"

	// pass sync fd if set
	if s.payload.Bwrap.Sync() != nil {
		fd := proc.ExtraFile(s.cmd, s.payload.Bwrap.Sync())
		s.payload.Sync = &fd
	}

	fmsg.VPrintln("starting shim via fsu:", s.cmd)
	// withhold messages to stderr
	fmsg.Suspend()
	if err := s.cmd.Start(); err != nil {
		return nil, fmsg.WrapErrorSuffix(err,
			"cannot start fsu:")
	}
	startTime := time.Now().UTC()
	return &startTime, nil
}

func (s *Shim) Serve(ctx context.Context) error {
	// kill shim if something goes wrong and an error is returned
	s.killFallback = make(chan error, 1)
	killShim := func() {
		if err := s.cmd.Process.Signal(os.Interrupt); err != nil {
			s.killFallback <- err
		}
	}
	defer func() { killShim() }()

	encodeErr := make(chan error)
	go func() { encodeErr <- s.encoder.Encode(s.payload) }()

	select {
	// encode return indicates setup completion
	case err := <-encodeErr:
		if err != nil {
			return fmsg.WrapErrorSuffix(err,
				"cannot transmit shim config:")
		}
		killShim = func() {}
		return nil

	// setup canceled before payload was accepted
	case <-ctx.Done():
		err := ctx.Err()
		if errors.Is(err, context.Canceled) {
			return fmsg.WrapError(errors.New("shim setup canceled"),
				"shim setup canceled")
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return fmsg.WrapError(errors.New("deadline exceeded waiting for shim"),
				"deadline exceeded waiting for shim")
		}
		// unreachable
		return err
	}
}
