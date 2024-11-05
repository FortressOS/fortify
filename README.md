Fortify
=======

[![Go Reference](https://pkg.go.dev/badge/git.ophivana.moe/security/fortify.svg)](https://pkg.go.dev/git.ophivana.moe/security/fortify)
[![Go Report Card](https://goreportcard.com/badge/git.ophivana.moe/security/fortify)](https://goreportcard.com/report/git.ophivana.moe/security/fortify)

Lets you run graphical applications as another user in a confined environment with a nice NixOS
module to configure target users and provide launchers and desktop files for your privileged user.

Why would you want this?

- It protects the desktop environment from applications.

- It protects applications from each other.

- It provides UID isolation on top of the standard application sandbox.

There are a few different things to set up for this to work:

- A set of users, each for a group of applications that should be allowed access to each other

- A tool to switch users, currently sudo and machinectl are supported.

- If you are running NixOS, the module in this repository can take care of launchers and desktop files in the privileged
  user's environment, as well as packages and extra home-manager configuration for target users.

If you have a flakes-enabled nix environment, you can try out the tool by running:

```shell
nix run git+https://git.ophivana.moe/security/fortify -- -h
```

## Module usage

The NixOS module currently requires home-manager and impermanence to function correctly.

To use the module, import it into your configuration with

```nix
{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.05";

    fortify = {
      url = "git+https://git.ophivana.moe/security/fortify";

      # Optional but recommended to limit the size of your system closure.
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, fortify, ... }:
  {
    nixosConfigurations.fortify = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        fortify.nixosModules.fortify
      ];
    };
  };
}
```

This adds the `environment.fortify` option:

```nix
{ pkgs, ... }:

{
  environment.fortify = {
    enable = true;
    user = "nixos";
    stateDir = "/var/lib/persist/module";
    target = {
      chronos = {
        launchers = {
          weechat.method = "sudo";
          claws-mail.capability.pulse = false;

          discord = {
            id = "dev.vencord.Vesktop";
            command = "vesktop --ozone-platform-hint=wayland";
            userns = true;
            useRealUid = true;
            dbus = {
              session =
                f:
                f {
                  talk = [ "org.kde.StatusNotifierWatcher" ];
                  own = [ ];
                  call = { };
                  broadcast = { };
                };
              system.filter = true;
            };
            share = pkgs.vesktop;
          };

          chromium = {
            id = "org.chromium.Chromium";
            userns = true;
            useRealUid = true;
            dbus = {
              system = {
                filter = true;
                talk = [
                  "org.bluez"
                  "org.freedesktop.Avahi"
                  "org.freedesktop.UPower"
                ];
              };
              session = f: f {
                talk = [
                  "org.freedesktop.DBus"
                  "org.freedesktop.FileManager1"
                  "org.freedesktop.Notifications"
                  "org.freedesktop.ScreenSaver"
                  "org.freedesktop.secrets"
                  "org.kde.kwalletd5"    
                  "org.kde.kwalletd6"
                ];   
                own = [
                  "org.chromium.Chromium.*"
                  "org.mpris.MediaPlayer2.org.chromium.Chromium.*"
                  "org.mpris.MediaPlayer2.chromium.*"
                ];
                call = { };
                broadcast = { };
              };
            };
          };
        };
        packages = with pkgs; [
          weechat
          claws-mail
          vesktop
          chromium
        ];
        persistence.directories = [
          ".config/weechat"
          ".claws-mail"
          ".config/vesktop"
        ];
        extraConfig = {
          programs.looking-glass-client.enable = true;
        };
      };
    };
  };
}
```

* `enable` determines whether the module should be enabled or not. Useful when sharing configurations between graphical
  and headless systems. Defaults to `false`.

* `user` specifies the privileged user with access to fortified applications.

* `stateDir` is the path to your persistent storage location. It is directly passed through to the impermanence module.

* `target` is an attribute set of submodules, where the attribute name is the username of the unprivileged target user.

  The available options are:

    * `packages`, the list of packages to make available in the target user's environment.

    * `persistence`, user persistence attribute set passed to impermanence.

    * `extraConfig`, extra home-manager configuration for the target user.

    * `launchers`, attribute set where the attribute name is the name of the launcher.

      The available options are:

        * `id`, the freedesktop application ID, primarily used by dbus, null to disable.

        * `command`, the command to run as the target user. Defaults to launcher name.

        * `dbus.session`, D-Bus session proxy custom configuration.

        * `dbus.configSystem`, D-Bus system proxy custom configuration, null to disable.

        * `env`, attrset of environment variables to set for the initial process in the sandbox.

        * `nix`, whether to allow nix daemon connections from within the sandbox.

        * `userns`, whether to allow userns within the sandbox.

        * `useRealUid`, whether to map to the real UID within the sandbox.

        * `net`, whether to allow network access within the sandbox.

        * `gpu`, target process GPU and driver access, null to follow Wayland or X capability.

        * `dev`, whether to allow full device access within the sandbox.

        * `extraPaths`, a list of extra paths to make available inside the sandbox.

        * `capability.wayland`, whether to share the Wayland socket.

        * `capability.x11`, whether to share the X11 socket and allow connection.

        * `capability.dbus`, whether to proxy D-Bus.

        * `capability.pulse`, whether to share the PulseAudio socket and cookie.

        * `share`, package containing desktop/icon files. Defaults to launcher name.

        * `method`, the launch method for the sandboxed program, can be `"sudo"`, `"systemd"`, `"simple"`.
