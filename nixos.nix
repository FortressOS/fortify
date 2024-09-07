{
  lib,
  pkgs,
  config,
  ...
}:

let
  inherit (lib)
    types
    mkOption
    mkEnableOption
    mkIf
    mapAttrs
    mapAttrsToList
    foldlAttrs
    optional
    ;

  cfg = config.environment.fortify;
in

{
  options = {
    environment.fortify = {
      enable = mkEnableOption "fortify";

      target = mkOption {
        default = { };
        type =
          let
            inherit (types)
              str
              enum
              bool
              package
              anything
              submodule
              listOf
              attrsOf
              nullOr
              ;
          in
          attrsOf (submodule {
            options = {
              packages = mkOption {
                type = listOf package;
                default = [ ];
                description = ''
                  List of extra packages to install via home-manager.
                '';
              };

              launchers = mkOption {
                type = attrsOf (submodule {
                  options = {
                    command = mkOption {
                      type = nullOr str;
                      default = null;
                      description = ''
                        Command to run as the target user.
                        Setting this to null will default command to wrapper name.
                      '';
                    };

                    capability = {
                      wayland = mkOption {
                        type = bool;
                        default = true;
                        description = ''
                          Whether to share the Wayland socket.
                        '';
                      };

                      x11 = mkOption {
                        type = bool;
                        default = false;
                        description = ''
                          Whether to share the X11 socket and allow connection.
                        '';
                      };

                      dbus = mkOption {
                        type = bool;
                        default = false;
                        description = ''
                          Whether to proxy D-Bus.
                        '';
                      };

                      pulse = mkOption {
                        type = bool;
                        default = true;
                        description = ''
                          Whether to share the PulseAudio socket and cookie.
                        '';
                      };
                    };

                    share = mkOption {
                      type = nullOr package;
                      default = null;
                      description = ''
                        Package containing share files.
                        Setting this to null will default package name to wrapper name.
                      '';
                    };

                    method = mkOption {
                      type = enum [
                        "fortify"
                        "fortify-sudo"
                        "sudo"
                      ];
                      default = "fortify";
                      description = ''
                        Launch method for the sandboxed program.
                      '';
                    };
                  };
                });
                default = { };
              };

              persistence = mkOption {
                type = submodule {
                  options = {
                    directories = mkOption {
                      type = listOf anything;
                      default = [ ];
                    };

                    files = mkOption {
                      type = listOf anything;
                      default = [ ];
                    };
                  };
                };
                description = ''
                  Per-user state passed to github:nix-community/impermanence.
                '';
              };

              extraConfig = mkOption {
                type = anything;
                default = { };
                description = "Extra home-manager configuration.";
              };
            };
          });
      };

      package = mkOption {
        type = types.package;
        default = pkgs.callPackage ./package.nix { };
        description = "Package providing fortify.";
      };

      user = mkOption {
        type = types.str;
        description = "Privileged user account.";
      };

      shell = mkOption {
        type = types.str;
        description = ''
          Shell set up to source home-manager for the privileged user.
          Required for setting up the environment of sandboxed programs.
        '';
      };

      stateDir = mkOption {
        type = types.str;
        description = ''
          The path to persistent storage where per-user state should be stored.
        '';
      };
    };
  };

  config = mkIf cfg.enable {
    environment.persistence.${cfg.stateDir}.users = mapAttrs (_: target: target.persistence) cfg.target;

    home-manager.users =
      mapAttrs (_: target: target.extraConfig // { home.packages = target.packages; }) cfg.target
      // {
        ${cfg.user}.home.packages =
          let
            wrap =
              user: launchers:
              mapAttrsToList (
                name: launcher:
                with launcher.capability;
                let
                  command = if launcher.command == null then name else launcher.command;
                  capArgs =
                    (if wayland then " -wayland" else "")
                    + (if x11 then " -X" else "")
                    + (if dbus then " -dbus" else "")
                    + (if pulse then " -pulse" else "")
                    + (if launcher.method == "fortify-sudo" then " -sudo" else "");
                in
                pkgs.writeShellScriptBin name (
                  if launcher.method == "sudo" then
                    ''
                      exec sudo -u ${user} -i ${command} $@
                    ''
                  else
                    ''
                      exec fortify${capArgs} -u ${user} ${cfg.shell} -c "exec ${command} $@"
                    ''
                )
              ) launchers;
          in
          foldlAttrs (
            acc: user: target:
            acc
            ++ (foldlAttrs (
              shares: name: launcher:
              let
                pkg = if launcher.share != null then launcher.share else pkgs.${name};
                link = source: "[ -d '${source}' ] && ln -sv '${source}' $out/share || true";
              in
              shares
              ++ optional (launcher.method == "fortify") (
                pkgs.runCommand "${name}-share" { } ''
                  mkdir -p $out/share
                  ${link "${pkg}/share/applications"}
                  ${link "${pkg}/share/icons"}
                  ${link "${pkg}/share/man"}
                ''
              )
            ) (wrap user target.launchers) target.launchers)
          ) [ cfg.package ] cfg.target;
      };

    security.polkit.extraConfig =
      let
        allowList = builtins.toJSON (mapAttrsToList (name: _: name) cfg.target);
      in
      ''
        polkit.addRule(function(action, subject) {
          if (action.id == "org.freedesktop.machine1.host-shell" &&
            ${allowList}.indexOf(action.lookup("user")) > -1 &&
            subject.user == "${cfg.user}") {
                return polkit.Result.YES;
          }
        });
      '';
  };
}
