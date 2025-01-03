{
  system,
  self,
  home-manager,
  nixosTest,
}:

nixosTest {
  name = "fortify";

  # adapted from nixos sway integration tests

  # testScriptWithTypes:49: error: Cannot call function of unknown type
  #           (machine.succeed if succeed else machine.execute)(
  #           ^
  # Found 1 error in 1 file (checked 1 source file)
  skipTypeCheck = true;

  nodes.machine =
    { lib, pkgs, ... }:
    {
      users.users.alice = {
        isNormalUser = true;
        description = "Alice Foobar";
        password = "foobar";
        uid = 1000;
      };

      home-manager.users.alice.home.stateVersion = "24.11";

      # Automatically login on tty1 as a normal user:
      services.getty.autologinUser = "alice";

      environment = {
        systemPackages = with pkgs; [
          # For glinfo and wayland-info:
          mesa-demos
          wayland-utils
          alacritty

          # For D-Bus tests:
          libnotify
          mako

          # For go tests:
          self.devShells.${system}.fhs
        ];

        variables = {
          SWAYSOCK = "/tmp/sway-ipc.sock";
          WLR_RENDERER = "pixman";
        };

        # To help with OCR:
        etc."xdg/foot/foot.ini".text = lib.generators.toINI { } {
          main = {
            font = "inconsolata:size=14";
          };
          colors = rec {
            foreground = "000000";
            background = "ffffff";
            regular2 = foreground;
          };
        };
      };

      fonts.packages = [ pkgs.inconsolata ];

      # Automatically configure and start Sway when logging in on tty1:
      programs.bash.loginShellInit = ''
        if [ "$(tty)" = "/dev/tty1" ]; then
          set -e

          mkdir -p ~/.config/sway
          sed s/Mod4/Mod1/ /etc/sway/config > ~/.config/sway/config

          sway --validate
          sway && touch /tmp/sway-exit-ok
        fi
      '';

      programs.sway.enable = true;

      # For PulseAudio tests:
      security.rtkit.enable = true;
      services.pipewire = {
        enable = true;
        alsa.enable = true;
        alsa.support32Bit = true;
        pulse.enable = true;
        jack.enable = true;
      };

      virtualisation.qemu.options = [
        # Need to switch to a different GPU driver than the default one (-vga std) so that Sway can launch:
        "-vga none -device virtio-gpu-pci"

        # Increase Go test compiler performance:
        "-smp 8"
      ];

      environment.fortify = {
        enable = true;
        stateDir = "/var/lib/fortify";
        users.alice = 0;
      };

      imports = [
        self.nixosModules.fortify
        home-manager.nixosModules.home-manager
      ];
    };

  testScript = ''
    import shlex
    import json

    q = shlex.quote
    NODE_GROUPS = ["nodes", "floating_nodes"]


    def swaymsg(command: str = "", succeed=True, type="command"):
        assert command != "" or type != "command", "Must specify command or type"
        shell = q(f"swaymsg -t {q(type)} -- {q(command)}")
        with machine.nested(
            f"sending swaymsg {shell!r}" + " (allowed to fail)" * (not succeed)
        ):
            ret = (machine.succeed if succeed else machine.execute)(
                f"su - alice -c {shell}"
            )

        # execute also returns a status code, but disregard.
        if not succeed:
            _, ret = ret

        if not succeed and not ret:
            return None

        parsed = json.loads(ret)
        return parsed


    def walk(tree):
        yield tree
        for group in NODE_GROUPS:
          for node in tree.get(group, []):
              yield from walk(node)


    def wait_for_window(pattern):
        def func(last_chance):
            nodes = (node["name"] for node in walk(swaymsg(type="get_tree")))

            if last_chance:
                nodes = list(nodes)
                machine.log(f"Last call! Current list of windows: {nodes}")

            return any(pattern in name for name in nodes)

        retry(func)


    def collect_state_ui(name):
        swaymsg(f"exec fortify ps > '/tmp/{name}.ps'")
        machine.copy_from_vm(f"/tmp/{name}.ps", "")
        swaymsg(f"exec fortify --json ps > '/tmp/{name}.json'")
        machine.copy_from_vm(f"/tmp/{name}.json", "")
        machine.screenshot(name)


    def check_state(command, enablements):
        instances = json.loads(machine.succeed("sudo -u alice -i XDG_RUNTIME_DIR=/run/user/1000 fortify --json ps"))
        if len(instances) != 1:
            raise Exception(f"unexpected state length {len(instances)}")
        instance = next(iter(instances.values()))

        if instance['config']['command'] != command:
            raise Exception(f"unexpected command {instance['config']['command']}")

        if instance['config']['confinement']['enablements'] != enablements:
            raise Exception(f"unexpected enablements {instance['config']['confinement']['enablements']}")


    def fortify(command):
        swaymsg(f"exec fortify {command}")

    start_all()
    machine.wait_for_unit("multi-user.target")

    # Run fortify Go tests outside of nix build in the background:
    machine.succeed("rm -rf /tmp/src && cp -a '${self.packages.${system}.fortify.src}' /tmp/src")
    machine.succeed("fortify-fhs -c '(cd /tmp/src && go generate ./... && go test ./... && touch /tmp/success-gotest)' &> /tmp/gotest &")

    # To check sway's version:
    print(machine.succeed("sway --version"))

    # Wait for Sway to complete startup:
    machine.wait_for_file("/run/user/1000/wayland-1")
    machine.wait_for_file("/tmp/sway-ipc.sock")

    # Create fortify aid 0 home directory:
    machine.succeed("install -dm 0700 -o 1000000 -g 1000000 /var/lib/fortify/u0/a0")

    # Start fortify outside Wayland session:
    print(machine.succeed("sudo -u alice -i fortify -v run -a 0 touch /tmp/success-bare"))
    machine.wait_for_file("/tmp/fortify.1000/tmpdir/0/success-bare")

    # Start fortify within Wayland session:
    fortify('-v run --wayland --dbus notify-send -a "NixOS Tests" "Test notification" "Notification from within sandbox." && touch /tmp/dbus-done')
    machine.wait_for_file("/tmp/dbus-done")
    collect_state_ui("dbus_notify_exited")
    machine.succeed("pkill -9 mako")

    # Start a terminal (foot) within fortify:
    fortify("run --wayland foot")
    wait_for_window("u0_a0@machine")
    machine.send_chars("clear; wayland-info && touch /tmp/success-client\n")
    machine.wait_for_file("/tmp/fortify.1000/tmpdir/0/success-client")
    collect_state_ui("foot_wayland_permissive")
    check_state(["foot"], 1)
    # Verify acl on XDG_RUNTIME_DIR:
    print(machine.succeed("getfacl --absolute-names --omit-header --numeric /run/user/1000 | grep 1000000"))
    machine.send_chars("exit\n")
    machine.wait_until_fails("pgrep foot")
    # Verify acl cleanup on XDG_RUNTIME_DIR:
    machine.wait_until_fails("getfacl --absolute-names --omit-header --numeric /run/user/1000 | grep 1000000")

    # Start a terminal (foot) within fortify from a terminal:
    swaymsg("exec foot $SHELL -c '(fortify run --wayland foot) & sleep 1 && fortify show --short $(fortify ps --short) && touch /tmp/ps-show-ok && cat'")
    wait_for_window("u0_a0@machine")
    machine.send_chars("clear; wayland-info && touch /tmp/success-client-term\n")
    machine.wait_for_file("/tmp/fortify.1000/tmpdir/0/success-client-term")
    machine.wait_for_file("/tmp/ps-show-ok")
    collect_state_ui("foot_wayland_permissive_term")
    check_state(["foot"], 1)
    machine.send_chars("exit\n")
    wait_for_window("foot")
    machine.send_key("ctrl-c")
    machine.wait_until_fails("pgrep foot")

    # Test PulseAudio (fortify does not support PipeWire yet):
    fortify("run --wayland --pulse foot")
    wait_for_window("u0_a0@machine")
    machine.send_chars("clear; pactl info && touch /tmp/success-pulse\n")
    machine.wait_for_file("/tmp/fortify.1000/tmpdir/0/success-pulse")
    collect_state_ui("pulse_wayland")
    check_state(["foot"], 9)
    machine.send_chars("exit\n")
    machine.wait_until_fails("pgrep foot")

    # Test XWayland (foot does not support X):
    fortify("run -X alacritty")
    wait_for_window("u0_a0@machine")
    machine.send_chars("clear; glinfo && touch /tmp/success-client-x11\n")
    machine.wait_for_file("/tmp/fortify.1000/tmpdir/0/success-client-x11")
    collect_state_ui("alacritty_x11_permissive")
    check_state(["alacritty"], 2)
    machine.send_chars("exit\n")
    machine.wait_until_fails("pgrep alacritty")

    # Exit Sway and verify process exit status 0:
    swaymsg("exit", succeed=False)
    machine.wait_until_fails("pgrep -x sway")
    machine.wait_for_file("/tmp/sway-exit-ok")

    # Print fortify runDir contents:
    print(machine.succeed("find /run/user/1000/fortify"))

    # Verify go test status:
    machine.wait_for_file("/tmp/gotest")
    print(machine.succeed("cat /tmp/gotest"))
    machine.wait_for_file("/tmp/success-gotest")
  '';
}
