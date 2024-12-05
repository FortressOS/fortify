{
  description = "fortify sandbox tool and nixos module";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11-small";
  };

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "aarch64-linux"
        "i686-linux"
        "x86_64-linux"
      ];

      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; });
    in
    {
      nixosModules.fortify = import ./nixos.nix;

      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor.${system};
        in
        {
          default = self.packages.${system}.fortify;

          fortify = pkgs.callPackage ./package.nix { };
        }
      );

      devShells = forAllSystems (system: {
        default = nixpkgsFor.${system}.mkShell {
          buildInputs = with nixpkgsFor.${system}; self.packages.${system}.fortify.buildInputs;
        };

        withPackage = nixpkgsFor.${system}.mkShell {
          buildInputs =
            with nixpkgsFor.${system};
            self.packages.${system}.fortify.buildInputs ++ [ self.packages.${system}.fortify ];
        };

        generateDoc =
          let
            pkgs = nixpkgsFor.${system};
            inherit (pkgs) lib;

            doc =
              let
                eval = lib.evalModules {
                  specialArgs = {
                    inherit pkgs;
                  };
                  modules = [ ./options.nix ];
                };
                cleanEval = lib.filterAttrsRecursive (n: v: n != "_module") eval;
              in
              pkgs.nixosOptionsDoc { inherit (cleanEval) options; };
            docText = pkgs.runCommand "fortify-module-docs.md" { } ''
              cat ${doc.optionsCommonMark} > $out
              sed -i '/*Declared by:*/,+1 d' $out
            '';
          in
          nixpkgsFor.${system}.mkShell {
            shellHook = ''
              exec cat ${docText} > options.md
            '';
          };
      });
    };
}
