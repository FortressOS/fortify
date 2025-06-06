package main

import (
	"context"
	"path"
	"strings"

	"git.gensokyo.uk/security/fortify/fst"
	"git.gensokyo.uk/security/fortify/internal"
	"git.gensokyo.uk/security/fortify/sandbox/seccomp"
)

func withNixDaemon(
	ctx context.Context,
	action string, command []string, net bool, updateConfig func(config *fst.Config) *fst.Config,
	app *appInfo, pathSet *appPathSet, dropShell bool, beforeFail func(),
) {
	mustRunAppDropShell(ctx, updateConfig(&fst.Config{
		ID: app.ID,

		Path: shellPath,
		Args: []string{shellPath, "-lc", "rm -f /nix/var/nix/daemon-socket/socket && " +
			// start nix-daemon
			"nix-daemon --store / & " +
			// wait for socket to appear
			"(while [ ! -S /nix/var/nix/daemon-socket/socket ]; do sleep 0.01; done) && " +
			// create directory so nix stops complaining
			"mkdir -p /nix/var/nix/profiles/per-user/root/channels && " +
			strings.Join(command, " && ") +
			// terminate nix-daemon
			" && pkill nix-daemon",
		},

		Username: "fortify",
		Shell:    shellPath,
		Data:     pathSet.homeDir,
		Dir:      path.Join("/data/data", app.ID),
		ExtraPerms: []*fst.ExtraPermConfig{
			{Path: dataHome, Execute: true},
			{Ensure: true, Path: pathSet.baseDir, Read: true, Write: true, Execute: true},
		},

		Identity: app.Identity,

		Container: &fst.ContainerConfig{
			Hostname: formatHostname(app.Name) + "-" + action,
			Userns:   true, // nix sandbox requires userns
			Net:      net,
			Seccomp:  seccomp.FilterMultiarch,
			Tty:      dropShell,
			Filesystem: []*fst.FilesystemConfig{
				{Src: pathSet.nixPath, Dst: "/nix", Write: true, Must: true},
			},
			Link: [][2]string{
				{app.CurrentSystem, "/run/current-system"},
				{"/run/current-system/sw/bin", "/bin"},
				{"/run/current-system/sw/bin", "/usr/bin"},
			},
			Etc:     path.Join(pathSet.cacheDir, "etc"),
			AutoEtc: true,
		},
	}), dropShell, beforeFail)
}

func withCacheDir(
	ctx context.Context,
	action string, command []string, workDir string,
	app *appInfo, pathSet *appPathSet, dropShell bool, beforeFail func()) {
	mustRunAppDropShell(ctx, &fst.Config{
		ID: app.ID,

		Path: shellPath,
		Args: []string{shellPath, "-lc", strings.Join(command, " && ")},

		Username: "nixos",
		Shell:    shellPath,
		Data:     pathSet.cacheDir, // this also ensures cacheDir via shim
		Dir:      path.Join("/data/data", app.ID, "cache"),
		ExtraPerms: []*fst.ExtraPermConfig{
			{Path: dataHome, Execute: true},
			{Ensure: true, Path: pathSet.baseDir, Read: true, Write: true, Execute: true},
			{Path: workDir, Execute: true},
		},

		Identity: app.Identity,

		Container: &fst.ContainerConfig{
			Hostname: formatHostname(app.Name) + "-" + action,
			Seccomp:  seccomp.FilterMultiarch,
			Tty:      dropShell,
			Filesystem: []*fst.FilesystemConfig{
				{Src: path.Join(workDir, "nix"), Dst: "/nix", Must: true},
				{Src: workDir, Dst: path.Join(fst.Tmp, "bundle"), Must: true},
			},
			Link: [][2]string{
				{app.CurrentSystem, "/run/current-system"},
				{"/run/current-system/sw/bin", "/bin"},
				{"/run/current-system/sw/bin", "/usr/bin"},
			},
			Etc:     path.Join(workDir, "etc"),
			AutoEtc: true,
		},
	}, dropShell, beforeFail)
}

func mustRunAppDropShell(ctx context.Context, config *fst.Config, dropShell bool, beforeFail func()) {
	if dropShell {
		config.Args = []string{shellPath, "-l"}
		mustRunApp(ctx, config, beforeFail)
		beforeFail()
		internal.Exit(0)
	}
	mustRunApp(ctx, config, beforeFail)
}
