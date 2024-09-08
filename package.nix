{
  lib,
  buildGoModule,
  makeBinaryWrapper,
  xdg-dbus-proxy,
  acl,
  xorg,
}:

buildGoModule rec {
  pname = "fortify";
  version = "1.0.4";

  src = ./.;
  vendorHash = null;

  ldflags = [
    "-s"
    "-w"
    "-X"
    "main.Version=v${version}"
  ];

  buildInputs = [
    acl
    xorg.libxcb
  ];

  nativeBuildInputs = [ makeBinaryWrapper ];

  postInstall = ''
    wrapProgram $out/bin/${pname} --prefix PATH : ${lib.makeBinPath [ xdg-dbus-proxy ]}
  '';
}
