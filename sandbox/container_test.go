package sandbox_test

import (
	"bytes"
	"context"
	"encoding/gob"
	"log"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"git.gensokyo.uk/security/fortify/fst"
	"git.gensokyo.uk/security/fortify/internal"
	"git.gensokyo.uk/security/fortify/internal/fmsg"
	"git.gensokyo.uk/security/fortify/ldd"
	"git.gensokyo.uk/security/fortify/sandbox"
	"git.gensokyo.uk/security/fortify/sandbox/seccomp"
	"git.gensokyo.uk/security/fortify/sandbox/vfs"
)

const (
	ignore  = "\x00"
	ignoreV = -1
)

func TestContainer(t *testing.T) {
	{
		oldVerbose := fmsg.Load()
		oldOutput := sandbox.GetOutput()
		internal.InstallFmsg(true)
		t.Cleanup(func() { fmsg.Store(oldVerbose) })
		t.Cleanup(func() { sandbox.SetOutput(oldOutput) })
	}

	testCases := []struct {
		name  string
		flags sandbox.HardeningFlags
		ops   *sandbox.Ops
		mnt   []*vfs.MountInfoEntry
		host  string
	}{
		{"minimal", 0, new(sandbox.Ops), nil, "test-minimal"},
		{"allow", sandbox.FAllowUserns | sandbox.FAllowNet | sandbox.FAllowTTY,
			new(sandbox.Ops), nil, "test-minimal"},
		{"tmpfs", 0,
			new(sandbox.Ops).
				Tmpfs(fst.Tmp, 0, 0755),
			[]*vfs.MountInfoEntry{
				e("/", fst.Tmp, "rw,nosuid,nodev,relatime", "tmpfs", "tmpfs", ignore),
			}, "test-tmpfs"},
		{"dev", sandbox.FAllowTTY, // go test output is not a tty
			new(sandbox.Ops).
				Dev("/dev").
				Mqueue("/dev/mqueue"),
			[]*vfs.MountInfoEntry{
				e("/", "/dev", "rw,nosuid,nodev,relatime", "tmpfs", "devtmpfs", ignore),
				e("/null", "/dev/null", "rw,nosuid", "devtmpfs", "devtmpfs", ignore),
				e("/zero", "/dev/zero", "rw,nosuid", "devtmpfs", "devtmpfs", ignore),
				e("/full", "/dev/full", "rw,nosuid", "devtmpfs", "devtmpfs", ignore),
				e("/random", "/dev/random", "rw,nosuid", "devtmpfs", "devtmpfs", ignore),
				e("/urandom", "/dev/urandom", "rw,nosuid", "devtmpfs", "devtmpfs", ignore),
				e("/tty", "/dev/tty", "rw,nosuid", "devtmpfs", "devtmpfs", ignore),
				e("/", "/dev/pts", "rw,nosuid,noexec,relatime", "devpts", "devpts", "rw,mode=620,ptmxmode=666"),
				e("/", "/dev/mqueue", "rw,nosuid,nodev,noexec,relatime", "mqueue", "mqueue", "rw"),
			}, ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			container := sandbox.New(ctx, "/usr/bin/sandbox.test", "-test.v",
				"-test.run=TestHelperCheckContainer", "--", "check", tc.host)
			container.Uid = 1000
			container.Gid = 100
			container.Hostname = tc.host
			container.CommandContext = commandContext
			container.Flags |= tc.flags
			container.Stdout, container.Stderr = os.Stdout, os.Stderr
			container.Ops = tc.ops
			if container.Args[5] == "" {
				if name, err := os.Hostname(); err != nil {
					t.Fatalf("cannot get hostname: %v", err)
				} else {
					container.Args[5] = name
				}
			}

			container.
				Tmpfs("/tmp", 0, 0755).
				Bind(os.Args[0], os.Args[0], 0).
				Mkdir("/usr/bin", 0755).
				Link(os.Args[0], "/usr/bin/sandbox.test").
				Place("/etc/hostname", []byte(container.Args[5]))
			// in case test has cgo enabled
			var libPaths []string
			if entries, err := ldd.ExecFilter(ctx,
				commandContext,
				func(v []byte) []byte {
					return bytes.SplitN(v, []byte("TestHelperInit\n"), 2)[1]
				}, os.Args[0]); err != nil {
				log.Fatalf("ldd: %v", err)
			} else {
				libPaths = ldd.Path(entries)
			}
			for _, name := range libPaths {
				container.Bind(name, name, 0)
			}
			// needs /proc to check mountinfo
			container.Proc("/proc")

			mnt := make([]*vfs.MountInfoEntry, 0, 3+len(libPaths))
			mnt = append(mnt, e("/sysroot", "/", "rw,nosuid,nodev,relatime", "tmpfs", "rootfs", ignore))
			mnt = append(mnt, tc.mnt...)
			mnt = append(mnt,
				e("/", "/tmp", "rw,nosuid,nodev,relatime", "tmpfs", "tmpfs", ignore),
				e(ignore, os.Args[0], "ro,nosuid,nodev,relatime", ignore, ignore, ignore),
				e(ignore, "/etc/hostname", "ro,nosuid,nodev,relatime", "tmpfs", "rootfs", ignore),
			)
			for _, name := range libPaths {
				mnt = append(mnt, e(ignore, name, "ro,nosuid,nodev,relatime", ignore, ignore, ignore))
			}
			mnt = append(mnt, e("/", "/proc", "rw,nosuid,nodev,noexec,relatime", "proc", "proc", "rw"))
			want := new(bytes.Buffer)
			if err := gob.NewEncoder(want).Encode(mnt); err != nil {
				t.Fatalf("cannot serialise expected mount points: %v", err)
			}
			container.Stdin = want

			if err := container.Start(); err != nil {
				fmsg.PrintBaseError(err, "start:")
				t.Fatalf("cannot start container: %v", err)
			} else if err = container.Serve(); err != nil {
				fmsg.PrintBaseError(err, "serve:")
				t.Errorf("cannot serve setup params: %v", err)
			}
			if err := container.Wait(); err != nil {
				fmsg.PrintBaseError(err, "wait:")
				t.Fatalf("wait: %v", err)
			}
		})
	}
}

func e(root, target, vfsOptstr, fsType, source, fsOptstr string) *vfs.MountInfoEntry {
	return &vfs.MountInfoEntry{
		ID:        ignoreV,
		Parent:    ignoreV,
		Devno:     vfs.DevT{ignoreV, ignoreV},
		Root:      root,
		Target:    target,
		VfsOptstr: vfsOptstr,
		OptFields: []string{ignore},
		FsType:    fsType,
		Source:    source,
		FsOptstr:  fsOptstr,
	}
}

func TestContainerString(t *testing.T) {
	container := sandbox.New(context.TODO(), "ldd", "/usr/bin/env")
	container.Flags |= sandbox.FAllowDevel
	container.Seccomp |= seccomp.FilterMultiarch
	want := `argv: ["ldd" "/usr/bin/env"], flags: 0x2, seccomp: 0x2e`
	if got := container.String(); got != want {
		t.Errorf("String: %s, want %s", got, want)
	}
}

func TestHelperInit(t *testing.T) {
	if len(os.Args) != 5 || os.Args[4] != "init" {
		return
	}
	sandbox.SetOutput(fmsg.Output{})
	sandbox.Init(fmsg.Prepare, internal.InstallFmsg)
}

func TestHelperCheckContainer(t *testing.T) {
	if len(os.Args) != 6 || os.Args[4] != "check" {
		return
	}

	t.Run("user", func(t *testing.T) {
		if uid := syscall.Getuid(); uid != 1000 {
			t.Errorf("Getuid: %d, want 1000", uid)
		}
		if gid := syscall.Getgid(); gid != 100 {
			t.Errorf("Getgid: %d, want 100", gid)
		}
	})
	t.Run("hostname", func(t *testing.T) {
		if name, err := os.Hostname(); err != nil {
			t.Fatalf("cannot get hostname: %v", err)
		} else if name != os.Args[5] {
			t.Errorf("Hostname: %q, want %q", name, os.Args[5])
		}

		if p, err := os.ReadFile("/etc/hostname"); err != nil {
			t.Fatalf("%v", err)
		} else if string(p) != os.Args[5] {
			t.Errorf("/etc/hostname: %q, want %q", string(p), os.Args[5])
		}
	})
	t.Run("mount", func(t *testing.T) {
		var mnt []*vfs.MountInfoEntry
		if err := gob.NewDecoder(os.Stdin).Decode(&mnt); err != nil {
			t.Fatalf("cannot receive expected mount points: %v", err)
		}

		var d *vfs.MountInfoDecoder
		if f, err := os.Open("/proc/self/mountinfo"); err != nil {
			t.Fatalf("cannot open mountinfo: %v", err)
		} else {
			d = vfs.NewMountInfoDecoder(f)
		}

		i := 0
		for cur := range d.Entries() {
			if i == len(mnt) {
				t.Errorf("got more than %d entries", len(mnt))
				break
			}

			// ugly hack but should be reliable and is less likely to false negative than comparing by parsed flags
			cur.VfsOptstr = strings.TrimSuffix(cur.VfsOptstr, ",relatime")
			cur.VfsOptstr = strings.TrimSuffix(cur.VfsOptstr, ",noatime")
			mnt[i].VfsOptstr = strings.TrimSuffix(mnt[i].VfsOptstr, ",relatime")
			mnt[i].VfsOptstr = strings.TrimSuffix(mnt[i].VfsOptstr, ",noatime")

			if !cur.EqualWithIgnore(mnt[i], "\x00") {
				t.Errorf("[FAIL] %s", cur)
			} else {
				t.Logf("[ OK ] %s", cur)
			}

			i++
		}
		if err := d.Err(); err != nil {
			t.Errorf("cannot parse mountinfo: %v", err)
		}

		if i != len(mnt) {
			t.Errorf("got %d entries, want %d", i, len(mnt))
		}
	})
}

func commandContext(ctx context.Context) *exec.Cmd {
	return exec.CommandContext(ctx, os.Args[0], "-test.v",
		"-test.run=TestHelperInit", "--", "init")
}
