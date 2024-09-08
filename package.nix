{
  acl,
  xorg,
  buildGoModule,
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
}