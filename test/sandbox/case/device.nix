{
  fs,
  ent,
  ignore,
}:
{
  name = "device";
  tty = false;
  device = true;
  mapRealUid = false;

  want = {
    env = [
      "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/65534/bus"
      "HOME=/var/lib/fortify/u0/a4"
      "PULSE_SERVER=unix:/run/user/65534/pulse/native"
      "SHELL=/run/current-system/sw/bin/bash"
      "TERM=linux"
      "USER=u0_a4"
      "WAYLAND_DISPLAY=wayland-0"
      "XDG_RUNTIME_DIR=/run/user/65534"
      "XDG_SESSION_CLASS=user"
      "XDG_SESSION_TYPE=tty"
    ];

    fs = fs "dead" {
      ".fortify" = fs "800001ed" { } null;
      bin = fs "800001ed" { sh = fs "80001ff" null null; } null;
      dev = fs "800001ed" null null;
      etc = fs "800001ed" {
        ".clean" = fs "80001ff" null null;
        ".host" = fs "800001c0" null null;
        ".updated" = fs "80001ff" null null;
        "NIXOS" = fs "80001ff" null null;
        "X11" = fs "80001ff" null null;
        "alsa" = fs "80001ff" null null;
        "bashrc" = fs "80001ff" null null;
        "binfmt.d" = fs "80001ff" null null;
        "dbus-1" = fs "80001ff" null null;
        "default" = fs "80001ff" null null;
        "dhcpcd.exit-hook" = fs "80001ff" null null;
        "fonts" = fs "80001ff" null null;
        "fstab" = fs "80001ff" null null;
        "fsurc" = fs "80001ff" null null;
        "fuse.conf" = fs "80001ff" null null;
        "group" = fs "180" null "fortify:x:65534:\n";
        "host.conf" = fs "80001ff" null null;
        "hostname" = fs "80001ff" null null;
        "hosts" = fs "80001ff" null null;
        "inputrc" = fs "80001ff" null null;
        "issue" = fs "80001ff" null null;
        "kbd" = fs "80001ff" null null;
        "locale.conf" = fs "80001ff" null null;
        "login.defs" = fs "80001ff" null null;
        "lsb-release" = fs "80001ff" null null;
        "lvm" = fs "80001ff" null null;
        "machine-id" = fs "80001ff" null null;
        "man_db.conf" = fs "80001ff" null null;
        "modprobe.d" = fs "80001ff" null null;
        "modules-load.d" = fs "80001ff" null null;
        "mtab" = fs "80001ff" null null;
        "nanorc" = fs "80001ff" null null;
        "netgroup" = fs "80001ff" null null;
        "nix" = fs "80001ff" null null;
        "nixos" = fs "80001ff" null null;
        "nscd.conf" = fs "80001ff" null null;
        "nsswitch.conf" = fs "80001ff" null null;
        "os-release" = fs "80001ff" null null;
        "pam" = fs "80001ff" null null;
        "pam.d" = fs "80001ff" null null;
        "passwd" = fs "180" null "u0_a4:x:65534:65534:Fortify:/var/lib/fortify/u0/a4:/run/current-system/sw/bin/bash\n";
        "pipewire" = fs "80001ff" null null;
        "pki" = fs "80001ff" null null;
        "polkit-1" = fs "80001ff" null null;
        "profile" = fs "80001ff" null null;
        "protocols" = fs "80001ff" null null;
        "resolv.conf" = fs "80001ff" null null;
        "resolvconf.conf" = fs "80001ff" null null;
        "rpc" = fs "80001ff" null null;
        "services" = fs "80001ff" null null;
        "set-environment" = fs "80001ff" null null;
        "shadow" = fs "80001ff" null null;
        "shells" = fs "80001ff" null null;
        "ssh" = fs "80001ff" null null;
        "ssl" = fs "80001ff" null null;
        "static" = fs "80001ff" null null;
        "subgid" = fs "80001ff" null null;
        "subuid" = fs "80001ff" null null;
        "sudoers" = fs "80001ff" null null;
        "sway" = fs "80001ff" null null;
        "sysctl.d" = fs "80001ff" null null;
        "systemd" = fs "80001ff" null null;
        "terminfo" = fs "80001ff" null null;
        "tmpfiles.d" = fs "80001ff" null null;
        "udev" = fs "80001ff" null null;
        "vconsole.conf" = fs "80001ff" null null;
        "xdg" = fs "80001ff" null null;
        "zoneinfo" = fs "80001ff" null null;
      } null;
      nix = fs "800001c0" { store = fs "801001fd" null null; } null;
      proc = fs "8000016d" null null;
      run = fs "800001ed" {
        current-system = fs "80001ff" null null;
        opengl-driver = fs "80001ff" null null;
        user = fs "800001ed" {
          "65534" = fs "800001c0" {
            bus = fs "10001fd" null null;
            pulse = fs "800001c0" { native = fs "10001b6" null null; } null;
            wayland-0 = fs "1000038" null null;
          } null;
        } null;
      } null;
      sys = fs "800001c0" {
        block = fs "800001ed" {
          fd0 = fs "80001ff" null null;
          loop0 = fs "80001ff" null null;
          loop1 = fs "80001ff" null null;
          loop2 = fs "80001ff" null null;
          loop3 = fs "80001ff" null null;
          loop4 = fs "80001ff" null null;
          loop5 = fs "80001ff" null null;
          loop6 = fs "80001ff" null null;
          loop7 = fs "80001ff" null null;
          sr0 = fs "80001ff" null null;
          vda = fs "80001ff" null null;
        } null;
        bus = fs "800001ed" null null;
        class = fs "800001ed" null null;
        dev = fs "800001ed" {
          block = fs "800001ed" null null;
          char = fs "800001ed" null null;
        } null;
        devices = fs "800001ed" null null;
      } null;
      tmp = fs "800001f8" { } null;
      usr = fs "800001c0" { bin = fs "800001ed" { env = fs "80001ff" null null; } null; } null;
      var = fs "800001c0" {
        lib = fs "800001c0" {
          fortify = fs "800001c0" {
            u0 = fs "800001c0" {
              a4 = fs "800001c0" {
                ".cache" = fs "800001ed" { ".keep" = fs "80001ff" null ""; } null;
                ".config" = fs "800001ed" { "environment.d" = fs "800001ed" { "10-home-manager.conf" = fs "80001ff" null null; } null; } null;
                ".local" = fs "800001ed" {
                  state = fs "800001ed" {
                    home-manager = fs "800001ed" { gcroots = fs "800001ed" { current-home = fs "80001ff" null null; } null; } null;
                    nix = fs "800001ed" {
                      profiles = fs "800001ed" {
                        home-manager = fs "80001ff" null null;
                        home-manager-1-link = fs "80001ff" null null;
                        profile = fs "80001ff" null null;
                        profile-1-link = fs "80001ff" null null;
                      } null;
                    } null;
                  } null;
                } null;
                ".nix-defexpr" = fs "800001ed" {
                  channels = fs "80001ff" null null;
                  channels_root = fs "80001ff" null null;
                } null;
                ".nix-profile" = fs "80001ff" null null;
              } null;
            } null;
          } null;
        } null;
        run = fs "800001ed" { nscd = fs "800001ed" { } null; } null;
      } null;
    } null;

    mount = [
      (ent "/sysroot" "/" "rw,nosuid,nodev,relatime" "tmpfs" "rootfs" "rw,uid=1000004,gid=1000004")
      (ent "/" "/proc" "rw,nosuid,nodev,noexec,relatime" "proc" "proc" "rw")
      (ent "/" "/.fortify" "rw,nosuid,nodev,relatime" "tmpfs" "tmpfs" "rw,size=4k,mode=755,uid=1000004,gid=1000004")
      (ent "/" "/dev" "ro,nosuid" "devtmpfs" "devtmpfs" ignore)
      (ent "/" "/dev/pts" "ro,nosuid,noexec,relatime" "devpts" "devpts" "rw,gid=3,mode=620,ptmxmode=666")
      (ent "/" "/dev/shm" "ro,nosuid,nodev" "tmpfs" "tmpfs" ignore)
      (ent "/" ignore ignore ignore ignore ignore) # order not deterministic
      (ent "/" ignore ignore ignore ignore ignore)
      (ent "/bin" "/bin" "ro,nosuid,nodev,relatime" "ext4" "/dev/disk/by-label/nixos" "rw")
      (ent "/usr/bin" "/usr/bin" "ro,nosuid,nodev,relatime" "ext4" "/dev/disk/by-label/nixos" "rw")
      (ent "/" "/nix/store" "ro,nosuid,nodev,relatime" "overlay" "overlay" "rw,lowerdir=/mnt-root/nix/.ro-store,upperdir=/mnt-root/nix/.rw-store/upper,workdir=/mnt-root/nix/.rw-store/work,uuid=on")
      (ent "/block" "/sys/block" "ro,nosuid,nodev,noexec,relatime" "sysfs" "sysfs" "rw")
      (ent "/bus" "/sys/bus" "ro,nosuid,nodev,noexec,relatime" "sysfs" "sysfs" "rw")
      (ent "/class" "/sys/class" "ro,nosuid,nodev,noexec,relatime" "sysfs" "sysfs" "rw")
      (ent "/dev" "/sys/dev" "ro,nosuid,nodev,noexec,relatime" "sysfs" "sysfs" "rw")
      (ent "/devices" "/sys/devices" "ro,nosuid,nodev,noexec,relatime" "sysfs" "sysfs" "rw")
      (ent "/dri" "/dev/dri" "rw,nosuid" "devtmpfs" "devtmpfs" ignore)
      (ent "/etc" ignore "ro,nosuid,nodev,relatime" "ext4" "/dev/disk/by-label/nixos" "rw")
      (ent "/" "/run/user" "rw,nosuid,nodev,relatime" "tmpfs" "tmpfs" "rw,size=4k,mode=755,uid=1000004,gid=1000004")
      (ent "/" "/run/user/65534" "rw,nosuid,nodev,relatime" "tmpfs" "tmpfs" "rw,size=8192k,mode=700,uid=1000004,gid=1000004")
      (ent "/tmp/fortify.1000/tmpdir/4" "/tmp" "rw,nosuid,nodev,relatime" "ext4" "/dev/disk/by-label/nixos" "rw")
      (ent "/var/lib/fortify/u0/a4" "/var/lib/fortify/u0/a4" "rw,nosuid,nodev,relatime" "ext4" "/dev/disk/by-label/nixos" "rw")
      (ent ignore "/etc/passwd" "ro,nosuid,nodev,relatime" "tmpfs" "rootfs" "rw,uid=1000004,gid=1000004")
      (ent ignore "/etc/group" "ro,nosuid,nodev,relatime" "tmpfs" "rootfs" "rw,uid=1000004,gid=1000004")
      (ent ignore "/run/user/65534/wayland-0" "ro,nosuid,nodev,relatime" "ext4" "/dev/disk/by-label/nixos" "rw")
      (ent ignore "/run/user/65534/pulse/native" "ro,nosuid,nodev,relatime" "tmpfs" "tmpfs" ignore)
      (ent ignore "/run/user/65534/bus" "ro,nosuid,nodev,relatime" "ext4" "/dev/disk/by-label/nixos" "rw")
      (ent "/" "/var/run/nscd" "rw,nosuid,nodev,relatime" "tmpfs" "tmpfs" "rw,size=8k,mode=755,uid=1000004,gid=1000004")
    ];

    seccomp = true;
  };
}
