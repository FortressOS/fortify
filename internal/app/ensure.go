package app

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"

	"git.ophivana.moe/cat/fortify/acl"
	"git.ophivana.moe/cat/fortify/internal"
	"git.ophivana.moe/cat/fortify/internal/verbose"
)

func (a *App) EnsureRunDir() {
	if err := os.Mkdir(a.runDirPath, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
		internal.Fatal("Error creating runtime directory:", err)
	}
}

func (a *App) EnsureRuntime() {
	if s, err := os.Stat(a.runtimePath); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			internal.Fatal("Runtime directory does not exist")
		}
		internal.Fatal("Error accessing runtime directory:", err)
	} else if !s.IsDir() {
		internal.Fatal(fmt.Sprintf("Path '%s' is not a directory", a.runtimePath))
	} else {
		if err = acl.UpdatePerm(a.runtimePath, a.UID(), acl.Execute); err != nil {
			internal.Fatal("Error preparing runtime directory:", err)
		} else {
			a.exit.RegisterRevertPath(a.runtimePath)
		}
		verbose.Printf("Runtime data dir '%s' configured\n", a.runtimePath)
	}
}

func (a *App) EnsureShare() {
	// acl is unnecessary as this directory is world executable
	if err := os.Mkdir(a.sharePath, 0701); err != nil && !errors.Is(err, fs.ErrExist) {
		internal.Fatal("Error creating shared directory:", err)
	}

	// workaround for launch method sudo
	if a.LaunchOption() == LaunchMethodSudo {
		// ensure child runtime directory (e.g. `/tmp/fortify.%d/%d.share`)
		cr := path.Join(a.sharePath, a.Uid+".share")
		if err := os.Mkdir(cr, 0700); err != nil && !errors.Is(err, fs.ErrExist) {
			internal.Fatal("Error creating child runtime directory:", err)
		} else {
			if err = acl.UpdatePerm(cr, a.UID(), acl.Read, acl.Write, acl.Execute); err != nil {
				internal.Fatal("Error preparing child runtime directory:", err)
			} else {
				a.exit.RegisterRevertPath(cr)
			}
			a.AppendEnv("XDG_RUNTIME_DIR", cr)
			a.AppendEnv("XDG_SESSION_CLASS", "user")
			a.AppendEnv("XDG_SESSION_TYPE", "tty")
			verbose.Printf("Child runtime data dir '%s' configured\n", cr)
		}
	}
}
