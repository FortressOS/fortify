package system

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"git.gensokyo.uk/security/fortify/acl"
	"git.gensokyo.uk/security/fortify/internal/fmsg"
)

// CopyFile registers an Op that copies path dst from src.
func (sys *I) CopyFile(dst, src string) *I {
	return sys.CopyFileType(Process, dst, src)
}

// CopyFileType registers a file copying Op labelled with type et.
func (sys *I) CopyFileType(et Enablement, dst, src string) *I {
	sys.lock.Lock()
	sys.ops = append(sys.ops, &Tmpfile{et, tmpfileCopy, dst, src})
	sys.lock.Unlock()

	sys.UpdatePermType(et, dst, acl.Read)

	return sys
}

// Link registers an Op that links dst to src.
func (sys *I) Link(oldname, newname string) *I {
	return sys.LinkFileType(Process, oldname, newname)
}

// LinkFileType registers a file linking Op labelled with type et.
func (sys *I) LinkFileType(et Enablement, oldname, newname string) *I {
	sys.lock.Lock()
	defer sys.lock.Unlock()

	sys.ops = append(sys.ops, &Tmpfile{et, tmpfileLink, newname, oldname})

	return sys
}

// Write registers an Op that writes dst with the contents of src.
func (sys *I) Write(dst, src string) *I {
	return sys.WriteType(Process, dst, src)
}

// WriteType registers a file writing Op labelled with type et.
func (sys *I) WriteType(et Enablement, dst, src string) *I {
	sys.lock.Lock()
	sys.ops = append(sys.ops, &Tmpfile{et, tmpfileWrite, dst, src})
	sys.lock.Unlock()

	sys.UpdatePermType(et, dst, acl.Read)

	return sys
}

const (
	tmpfileCopy uint8 = iota
	tmpfileLink
	tmpfileWrite
)

type Tmpfile struct {
	et       Enablement
	method   uint8
	dst, src string
}

func (t *Tmpfile) Type() Enablement {
	return t.et
}

func (t *Tmpfile) apply(_ *I) error {
	switch t.method {
	case tmpfileCopy:
		fmsg.VPrintln("publishing tmpfile", t)
		return fmsg.WrapErrorSuffix(copyFile(t.dst, t.src),
			fmt.Sprintf("cannot copy tmpfile %q:", t.dst))
	case tmpfileLink:
		fmsg.VPrintln("linking tmpfile", t)
		return fmsg.WrapErrorSuffix(os.Link(t.src, t.dst),
			fmt.Sprintf("cannot link tmpfile %q:", t.dst))
	case tmpfileWrite:
		fmsg.VPrintln("writing", t)
		return fmsg.WrapErrorSuffix(os.WriteFile(t.dst, []byte(t.src), 0600),
			fmt.Sprintf("cannot write tmpfile %q:", t.dst))
	default:
		panic("invalid tmpfile method " + strconv.Itoa(int(t.method)))
	}
}

func (t *Tmpfile) revert(_ *I, ec *Criteria) error {
	if ec.hasType(t) {
		fmsg.VPrintf("removing tmpfile %q", t.dst)
		return fmsg.WrapErrorSuffix(os.Remove(t.dst),
			fmt.Sprintf("cannot remove tmpfile %q:", t.dst))
	} else {
		fmsg.VPrintf("skipping tmpfile %q", t.dst)
		return nil
	}
}

func (t *Tmpfile) Is(o Op) bool {
	t0, ok := o.(*Tmpfile)
	return ok && t0 != nil && *t == *t0
}

func (t *Tmpfile) Path() string {
	if t.method == tmpfileWrite {
		return fmt.Sprintf("(%d bytes of data)", len(t.src))
	}
	return t.src
}

func (t *Tmpfile) String() string {
	switch t.method {
	case tmpfileCopy:
		return fmt.Sprintf("%q from %q", t.dst, t.src)
	case tmpfileLink:
		return fmt.Sprintf("%q from %q", t.dst, t.src)
	case tmpfileWrite:
		return fmt.Sprintf("%d bytes of data to %q", len(t.src), t.dst)
	default:
		panic("invalid tmpfile method " + strconv.Itoa(int(t.method)))
	}
}

func copyFile(dst, src string) error {
	dstD, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}

	srcD, err := os.Open(src)
	if err != nil {
		return errors.Join(err, dstD.Close())
	}

	_, err = io.Copy(dstD, srcD)
	return errors.Join(err, dstD.Close(), srcD.Close())
}
