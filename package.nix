{
  lib,
  stdenv,
  buildGoModule,
  makeBinaryWrapper,
  xdg-dbus-proxy,
  bubblewrap,
  pkg-config,
  libffi,
  libseccomp,
  acl,
  wayland,
  wayland-protocols,
  wayland-scanner,
  xorg,

  glibc, # for ldd
  withStatic ? stdenv.hostPlatform.isStatic,
}:

buildGoModule rec {
  pname = "fortify";
  version = "0.2.18";

  src = builtins.path {
    name = "${pname}-src";
    path = lib.cleanSource ./.;
    filter =
      path: type:
      !(type == "regular" && lib.hasSuffix ".nix" path)
      && !(type == "directory" && lib.hasSuffix "/cmd/fsu" path);
  };
  vendorHash = null;

  ldflags =
    lib.attrsets.foldlAttrs
      (
        ldflags: name: value:
        ldflags ++ [ "-X git.gensokyo.uk/security/fortify/internal.${name}=${value}" ]
      )
      (
        [
          "-s -w"
        ]
        ++ lib.optionals withStatic [
          "-linkmode external"
          "-extldflags \"-static\""
        ]
      )
      {
        Version = "v${version}";
        Fsu = "/run/wrappers/bin/fsu";
      };

  # nix build environment does not allow acls
  env.GO_TEST_SKIP_ACL = 1;

  buildInputs =
    [
      libffi
      libseccomp
      acl
      wayland
      wayland-protocols
    ]
    ++ (with xorg; [
      libxcb
      libXau
      libXdmcp
    ]);

  nativeBuildInputs = [
    pkg-config
    wayland-scanner
    makeBinaryWrapper
  ];

  preBuild = ''
    HOME="$(mktemp -d)" PATH="${pkg-config}/bin:$PATH" go generate ./...
  '';

  postInstall = ''
    install -D --target-directory=$out/share/zsh/site-functions comp/*

    mkdir "$out/libexec"
    mv "$out"/bin/* "$out/libexec/"

    makeBinaryWrapper "$out/libexec/fortify" "$out/bin/fortify" \
      --inherit-argv0 --prefix PATH : ${
        lib.makeBinPath [
          glibc
          bubblewrap
          xdg-dbus-proxy
        ]
      }
  '';
}
