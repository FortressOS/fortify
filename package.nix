{
  lib,
  buildGoModule,
  makeBinaryWrapper,
  xdg-dbus-proxy,
  bubblewrap,
  acl,
  xorg,
}:

buildGoModule rec {
  pname = "fortify";
  version = "0.0.10";

  src = ./.;
  vendorHash = null;

  ldflags = [
    "-s"
    "-w"
    "-X"
    "main.Version=v${version}"
    "-X"
    "main.FortifyPath=${placeholder "out"}/bin/.fortify-wrapped"
  ];

  buildInputs = [
    acl
    xorg.libxcb
  ];

  nativeBuildInputs = [ makeBinaryWrapper ];

  postInstall = ''
    wrapProgram $out/bin/${pname} --prefix PATH : ${
      lib.makeBinPath [
        bubblewrap
        xdg-dbus-proxy
      ]
    }

    mv $out/bin/fsu $out/bin/.fsu
  '';
}
