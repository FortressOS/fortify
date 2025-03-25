package sandbox

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"git.gensokyo.uk/security/fortify/sandbox/seccomp"
)

const (
	// time to wait for linger processes after death of initial process
	residualProcessTimeout = 5 * time.Second

	// intermediate tmpfs mount point
	basePath = "/tmp"

	// setup params file descriptor
	setupEnv = "FORTIFY_SETUP"
)

type initParams struct {
	Params

	HostUid, HostGid int
	// extra files count
	Count int
	// verbosity pass through
	Verbose bool
}

func Init(prepare func(prefix string), setVerbose func(verbose bool)) {
	runtime.LockOSThread()
	prepare("init")

	if os.Getpid() != 1 {
		log.Fatal("this process must run as pid 1")
	}

	/*
		receive setup payload
	*/

	var (
		params      initParams
		closeSetup  func() error
		setupFile   *os.File
		offsetSetup int
	)
	if f, err := Receive(setupEnv, &params, &setupFile); err != nil {
		if errors.Is(err, ErrInvalid) {
			log.Fatal("invalid setup descriptor")
		}
		if errors.Is(err, ErrNotSet) {
			log.Fatal("FORTIFY_SETUP not set")
		}

		log.Fatalf("cannot decode init setup payload: %v", err)
	} else {
		if params.Ops == nil {
			log.Fatal("invalid setup parameters")
		}
		if params.ParentPerm == 0 {
			params.ParentPerm = 0755
		}

		setVerbose(params.Verbose)
		msg.Verbose("received setup parameters")
		closeSetup = f
		offsetSetup = int(setupFile.Fd() + 1)
	}

	// write uid/gid map here so parent does not need to set dumpable
	if err := SetDumpable(SUID_DUMP_USER); err != nil {
		log.Fatalf("cannot set SUID_DUMP_USER: %s", err)
	}
	if err := os.WriteFile("/proc/self/uid_map",
		append([]byte{}, strconv.Itoa(params.Uid)+" "+strconv.Itoa(params.HostUid)+" 1\n"...),
		0); err != nil {
		log.Fatalf("%v", err)
	}
	if err := os.WriteFile("/proc/self/setgroups",
		[]byte("deny\n"),
		0); err != nil && !os.IsNotExist(err) {
		log.Fatalf("%v", err)
	}
	if err := os.WriteFile("/proc/self/gid_map",
		append([]byte{}, strconv.Itoa(params.Gid)+" "+strconv.Itoa(params.HostGid)+" 1\n"...),
		0); err != nil {
		log.Fatalf("%v", err)
	}
	if err := SetDumpable(SUID_DUMP_DISABLE); err != nil {
		log.Fatalf("cannot set SUID_DUMP_DISABLE: %s", err)
	}

	oldmask := syscall.Umask(0)
	if params.Hostname != "" {
		if err := syscall.Sethostname([]byte(params.Hostname)); err != nil {
			log.Fatalf("cannot set hostname: %v", err)
		}
	}

	// cache sysctl before pivot_root
	LastCap()

	/*
		set up mount points from intermediate root
	*/

	if err := syscall.Mount("", "/", "",
		syscall.MS_SILENT|syscall.MS_SLAVE|syscall.MS_REC,
		""); err != nil {
		log.Fatalf("cannot make / rslave: %v", err)
	}

	for i, op := range *params.Ops {
		if op == nil {
			log.Fatalf("invalid op %d", i)
		}

		if err := op.early(&params.Params); err != nil {
			msg.PrintBaseErr(err,
				fmt.Sprintf("cannot prepare op %d:", i))
			msg.BeforeExit()
			os.Exit(1)
		}
	}

	if err := syscall.Mount("rootfs", basePath, "tmpfs",
		syscall.MS_NODEV|syscall.MS_NOSUID,
		""); err != nil {
		log.Fatalf("cannot mount intermediate root: %v", err)
	}
	if err := os.Chdir(basePath); err != nil {
		log.Fatalf("cannot enter base path: %v", err)
	}

	if err := os.Mkdir(sysrootDir, 0755); err != nil {
		log.Fatalf("%v", err)
	}
	if err := syscall.Mount(sysrootDir, sysrootDir, "",
		syscall.MS_SILENT|syscall.MS_MGC_VAL|syscall.MS_BIND|syscall.MS_REC,
		""); err != nil {
		log.Fatalf("cannot bind sysroot: %v", err)
	}

	if err := os.Mkdir(hostDir, 0755); err != nil {
		log.Fatalf("%v", err)
	}
	if err := syscall.PivotRoot(basePath, hostDir); err != nil {
		log.Fatalf("cannot pivot into intermediate root: %v", err)
	}
	if err := os.Chdir("/"); err != nil {
		log.Fatalf("%v", err)
	}

	for i, op := range *params.Ops {
		// ops already checked during early setup
		msg.Verbosef("%s %s", op.prefix(), op)
		if err := op.apply(&params.Params); err != nil {
			msg.PrintBaseErr(err,
				fmt.Sprintf("cannot apply op %d:", i))
			msg.BeforeExit()
			os.Exit(1)
		}
	}

	/*
		pivot to sysroot
	*/

	if err := syscall.Mount(hostDir, hostDir, "",
		syscall.MS_SILENT|syscall.MS_REC|syscall.MS_PRIVATE,
		""); err != nil {
		log.Fatalf("cannot make host root rprivate: %v", err)
	}
	if err := syscall.Unmount(hostDir, syscall.MNT_DETACH); err != nil {
		log.Fatalf("cannot unmount host root: %v", err)
	}

	{
		var fd int
		if err := IgnoringEINTR(func() (err error) {
			fd, err = syscall.Open("/", syscall.O_DIRECTORY|syscall.O_RDONLY, 0)
			return
		}); err != nil {
			log.Fatalf("cannot open intermediate root: %v", err)
		}
		if err := os.Chdir(sysrootPath); err != nil {
			log.Fatalf("%v", err)
		}

		if err := syscall.PivotRoot(".", "."); err != nil {
			log.Fatalf("cannot pivot into sysroot: %v", err)
		}
		if err := syscall.Fchdir(fd); err != nil {
			log.Fatalf("cannot re-enter intermediate root: %v", err)
		}
		if err := syscall.Unmount(".", syscall.MNT_DETACH); err != nil {
			log.Fatalf("cannot unmount intemediate root: %v", err)
		}
		if err := os.Chdir("/"); err != nil {
			log.Fatalf("%v", err)
		}

		if err := syscall.Close(fd); err != nil {
			log.Fatalf("cannot close intermediate root: %v", err)
		}
	}

	/*
		caps/securebits and seccomp filter
	*/

	if _, _, errno := syscall.Syscall(PR_SET_NO_NEW_PRIVS, 1, 0, 0); errno != 0 {
		log.Fatalf("prctl(PR_SET_NO_NEW_PRIVS): %v", errno)
	}
	if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0); errno != 0 {
		log.Fatalf("cannot clear the ambient capability set: %v", errno)
	}
	for i := uintptr(0); i <= LastCap(); i++ {
		if _, _, errno := syscall.Syscall(syscall.SYS_PRCTL, syscall.PR_CAPBSET_DROP, i, 0); errno != 0 {
			log.Fatalf("cannot drop capability from bonding set: %v", errno)
		}
	}
	if err := capset(
		&capHeader{_LINUX_CAPABILITY_VERSION_3, 0},
		&[2]capData{{0, 0, 0}, {0, 0, 0}},
	); err != nil {
		log.Fatalf("cannot capset: %v", err)
	}

	if err := seccomp.Load(params.Flags.seccomp(params.Seccomp)); err != nil {
		log.Fatalf("cannot load syscall filter: %v", err)
	}

	/*
		pass through extra files
	*/

	extraFiles := make([]*os.File, params.Count)
	for i := range extraFiles {
		extraFiles[i] = os.NewFile(uintptr(offsetSetup+i), "extra file "+strconv.Itoa(i))
	}
	syscall.Umask(oldmask)

	/*
		prepare initial process
	*/

	cmd := exec.Command(params.Path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Args = params.Args
	cmd.Env = params.Env
	cmd.ExtraFiles = extraFiles
	cmd.Dir = params.Dir

	if err := cmd.Start(); err != nil {
		log.Fatalf("%v", err)
	}
	msg.Suspend()

	/*
		close setup pipe
	*/

	if err := closeSetup(); err != nil {
		log.Println("cannot close setup pipe:", err)
		// not fatal
	}

	/*
		perform init duties
	*/

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
			log.Println("unexpected wait4 response:", err)
		}

		close(done)
	}()

	// closed after residualProcessTimeout has elapsed after initial process death
	timeout := make(chan struct{})

	r := 2
	for {
		select {
		case s := <-sig:
			if msg.Resume() {
				msg.Verbosef("terminating on %s after process start", s.String())
			} else {
				msg.Verbosef("terminating on %s", s.String())
			}
			msg.BeforeExit()
			os.Exit(0)
		case w := <-info:
			if w.wpid == cmd.Process.Pid {
				// initial process exited, output is most likely available again
				msg.Resume()

				switch {
				case w.wstatus.Exited():
					r = w.wstatus.ExitStatus()
					msg.Verbosef("initial process exited with code %d", w.wstatus.ExitStatus())
				case w.wstatus.Signaled():
					r = 128 + int(w.wstatus.Signal())
					msg.Verbosef("initial process exited with signal %s", w.wstatus.Signal())
				default:
					r = 255
					msg.Verbosef("initial process exited with status %#x", w.wstatus)
				}

				go func() {
					time.Sleep(residualProcessTimeout)
					close(timeout)
				}()
			}
		case <-done:
			msg.BeforeExit()
			os.Exit(r)
		case <-timeout:
			log.Println("timeout exceeded waiting for lingering processes")
			msg.BeforeExit()
			os.Exit(r)
		}
	}
}

// TryArgv0 calls [Init] if the last element of argv0 is "init".
func TryArgv0(v Msg, prepare func(prefix string), setVerbose func(verbose bool)) {
	if len(os.Args) > 0 && path.Base(os.Args[0]) == "init" {
		msg = v
		Init(prepare, setVerbose)
		msg.BeforeExit()
		os.Exit(0)
	}
}
