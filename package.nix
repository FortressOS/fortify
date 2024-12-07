{
  lib,
  buildGoModule,
  makeBinaryWrapper,
  xdg-dbus-proxy,
  bubblewrap,
  pkg-config,
  acl,
  wayland,
  wayland-scanner,
  wayland-protocols,
  xorg,
}:

buildGoModule rec {
  pname = "fortify";
  version = "0.2.2";

  src = ./.;
  vendorHash = null;

  ldflags =
    lib.attrsets.foldlAttrs
      (
        ldflags: name: value:
        ldflags
        ++ [
          "-X"
          "git.ophivana.moe/security/fortify/internal.${name}=${value}"
        ]
      )
      [
        "-s"
        "-w"
        "-X"
        "main.Fmain=${placeholder "out"}/libexec/fortify"
        "-X"
        "main.Fshim=${placeholder "out"}/libexec/fshim"
      ]
      {
        Version = "v${version}";
        Fsu = "/run/wrappers/bin/fsu";
        Finit = "${placeholder "out"}/libexec/finit";
      };

  buildInputs = [
    acl
    wayland
    wayland-protocols
    xorg.libxcb
  ];

  nativeBuildInputs = [
    pkg-config
    wayland-scanner
    makeBinaryWrapper
  ];

  preConfigure = ''
    HOME=$(mktemp -d) go generate ./...
  '';

  postInstall = ''
    install -D --target-directory=$out/share/zsh/site-functions comp/*

    mkdir "$out/libexec"
    mv "$out"/bin/* "$out/libexec/"

    makeBinaryWrapper "$out/libexec/fortify" "$out/bin/fortify" \
      --inherit-argv0 --prefix PATH : ${
        lib.makeBinPath [
          bubblewrap
          xdg-dbus-proxy
        ]
      }
  '';
}
