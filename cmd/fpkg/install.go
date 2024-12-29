package main

import (
	"encoding/json"
	"flag"
	"os"
	"path"

	"git.gensokyo.uk/security/fortify/fst"
	"git.gensokyo.uk/security/fortify/internal/fmsg"
)

func actionInstall(args []string) {
	set := flag.NewFlagSet("install", flag.ExitOnError)
	var (
		dropShellInstall  bool
		dropShellActivate bool
	)
	set.BoolVar(&dropShellInstall, "si", false, "Drop to a shell on installation")
	set.BoolVar(&dropShellActivate, "sa", false, "Drop to a shell on activation")

	// Ignore errors; set is set for ExitOnError.
	_ = set.Parse(args)

	args = set.Args()

	if len(args) != 1 {
		fmsg.Fatal("invalid argument")
	}
	pkgPath := args[0]
	if !path.IsAbs(pkgPath) {
		if dir, err := os.Getwd(); err != nil {
			fmsg.Fatalf("cannot get current directory: %v", err)
		} else {
			pkgPath = path.Join(dir, pkgPath)
		}
	}

	/*
		Look up paths to programs started by fpkg.
		This is done here to ease error handling as cleanup is not yet required.
	*/

	var (
		_     = lookPath("zstd")
		tar   = lookPath("tar")
		chmod = lookPath("chmod")
		rm    = lookPath("rm")
	)

	/*
		Extract package and set up for cleanup.
	*/

	var workDir string
	if p, err := os.MkdirTemp("", "fpkg.*"); err != nil {
		fmsg.Fatalf("cannot create temporary directory: %v", err)
	} else {
		workDir = p
	}
	cleanup := func() {
		// should be faster than a native implementation
		mustRun(chmod, "-R", "+w", workDir)
		mustRun(rm, "-rf", workDir)
	}
	beforeRunFail.Store(&cleanup)

	mustRun(tar, "-C", workDir, "-xf", pkgPath)

	/*
		Parse bundle and app metadata, do pre-install checks.
	*/

	bundle := loadBundleInfo(path.Join(workDir, "bundle.json"), cleanup)
	pathSet := pathSetByApp(bundle.ID)

	app := bundle
	if s, err := os.Stat(pathSet.metaPath); err != nil {
		if !os.IsNotExist(err) {
			cleanup()
			fmsg.Fatalf("cannot access %q: %v", pathSet.metaPath, err)
			panic("unreachable")
		}
		// did not modify app, clean installation condition met later
	} else if s.IsDir() {
		cleanup()
		fmsg.Fatalf("metadata path %q is not a file", pathSet.metaPath)
		panic("unreachable")
	} else {
		app = loadBundleInfo(pathSet.metaPath, cleanup)
		if app.ID != bundle.ID {
			cleanup()
			fmsg.Fatalf("app %q claims to have identifier %q", bundle.ID, app.ID)
		}
		// sec: should verify credentials
	}

	if app != bundle {
		// do not try to re-install
		if app.Launcher == bundle.Launcher {
			cleanup()
			fmsg.Printf("package %q is identical to local application %q", pkgPath, app.ID)
			fmsg.Exit(0)
		}

		// AppID determines uid
		if app.AppID != bundle.AppID {
			cleanup()
			fmsg.Fatalf("package %q app id %d differs from installed %d", pkgPath, bundle.AppID, app.AppID)
			panic("unreachable")
		}

		// sec: should compare version string
		fmsg.VPrintf("installing application %q version %q over local %q", bundle.ID, bundle.Version, app.Version)
	} else {
		fmsg.VPrintf("application %q clean installation", bundle.ID)
		// sec: should install credentials
	}

	/*
		Setup steps for files owned by the target user.
	*/

	installConfig := &fst.Config{
		ID: bundle.ID,
		Command: []string{shell, "-lc", "export BUNDLE=" + fst.Tmp + "/bundle && " + // export inner bundle path in the environment
			"mkdir -p etc && chmod -R +w etc && rm -rf etc && cp -dRf $BUNDLE/etc etc && " + // replace inner /etc
			"mkdir -p nix && chmod -R +w nix && rm -rf nix && cp -dRf /nix nix && " + // replace inner /nix
			"nix copy --offline --no-check-sigs --all --from file://$BUNDLE/res --to $PWD && " + // copy from binary cache
			"chmod 0755 .", // make cache directory world-readable for autoetc
		},
		Confinement: fst.ConfinementConfig{
			AppID:    bundle.AppID,
			Username: "nixos",
			Inner:    path.Join("/data/data", bundle.ID, "cache"),
			Outer:    pathSet.cacheDir, // this also ensures cacheDir via fshim
			Sandbox: &fst.SandboxConfig{
				Hostname:     formatHostname(bundle.Name) + "-install",
				NoNewSession: dropShellInstall, // nix copy should not need job control
				Filesystem: []*fst.FilesystemConfig{
					{Src: path.Join(workDir, "nix"), Dst: "/nix", Must: true},
					{Src: workDir, Dst: path.Join(fst.Tmp, "bundle"), Must: true},
				},
				Link: [][2]string{
					{bundle.CurrentSystem, "/run/current-system"},
					{"/run/current-system/sw/bin", "/bin"},
					{"/run/current-system/sw/bin", "/usr/bin"},
				},
				Etc:     path.Join(workDir, "etc"),
				AutoEtc: true,
			},
			ExtraPerms: []*fst.ExtraPermConfig{
				{Path: dataHome, Execute: true},
				{Ensure: true, Path: pathSet.baseDir, Read: true, Write: true, Execute: true},
				{Path: workDir, Execute: true},
			},
		},
	}

	if dropShellInstall {
		installConfig.Command = []string{shell, "-l"}
		fortifyApp(installConfig, cleanup)
		cleanup()
		fmsg.Exit(0)
	}
	fortifyApp(installConfig, cleanup)

	/*
		Activate home-manager generation.
	*/

	activateConfig := &fst.Config{
		ID: bundle.ID,
		Command: []string{shell, "-lc", "mkdir -p .local/state/{nix,home-manager} && chmod -R +w .local/state/{nix,home-manager} && rm -rf .local/state/{nix,home-manager} && " + // clean up broken links
			"nix-daemon --store / & " + // start nix-daemon
			"(while [ ! -S /nix/var/nix/daemon-socket/socket ]; do sleep 0.01; done) && " + // wait for socket to appear
			bundle.ActivationPackage + "/activate && " + // run activation script
			"pkill nix-daemon", // terminate nix-daemon
		},
		Confinement: fst.ConfinementConfig{
			AppID:    bundle.AppID,
			Groups:   bundle.Groups,
			Username: "fortify",
			Inner:    path.Join("/data/data", bundle.ID),
			Outer:    pathSet.homeDir,
			Sandbox: &fst.SandboxConfig{
				Hostname:     formatHostname(bundle.Name) + "-activate",
				UserNS:       true,              // nix sandbox requires userns
				NoNewSession: dropShellActivate, // home-manager activation should not need job control
				Filesystem: []*fst.FilesystemConfig{
					{Src: pathSet.nixPath, Dst: "/nix", Write: true, Must: true},
				},
				Link: [][2]string{
					{bundle.CurrentSystem, "/run/current-system"},
					{"/run/current-system/sw/bin", "/bin"},
					{"/run/current-system/sw/bin", "/usr/bin"},
				},
				Etc:     path.Join(pathSet.cacheDir, "etc"),
				AutoEtc: true,
			},
			ExtraPerms: []*fst.ExtraPermConfig{
				{Path: dataHome, Execute: true},
				{Ensure: true, Path: pathSet.baseDir, Read: true, Write: true, Execute: true},
				{Path: workDir, Execute: true},
			},
		},
	}

	if dropShellActivate {
		activateConfig.Command = []string{shell, "-l"}
		fortifyApp(activateConfig, cleanup)
		cleanup()
		fmsg.Exit(0)
	}
	fortifyApp(activateConfig, cleanup)

	/*
		Installation complete. Write metadata to block re-installs or downgrades.
	*/

	// serialise metadata to ensure consistency
	if f, err := os.OpenFile(pathSet.metaPath+"~", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644); err != nil {
		cleanup()
		fmsg.Fatalf("cannot create metadata file: %v", err)
		panic("unreachable")
	} else if err = json.NewEncoder(f).Encode(bundle); err != nil {
		cleanup()
		fmsg.Fatalf("cannot write metadata: %v", err)
		panic("unreachable")
	} else if err = f.Close(); err != nil {
		fmsg.Printf("cannot close metadata file: %v", err)
		// not fatal
	}

	if err := os.Rename(pathSet.metaPath+"~", pathSet.metaPath); err != nil {
		cleanup()
		fmsg.Fatalf("cannot rename metadata file: %v", err)
		panic("unreachable")
	}

	cleanup()
}
