{
  inputs = {
    nixpkgs = {
      url = "github:nixos/nixpkgs/nixpkgs-unstable";
      # follows = "comity/nixpkgs";
    };
    flake-utils = {
      url = "github:numtide/flake-utils";
      # follows = "comity/flake-utils";
    };
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
      # follows = "comity/flake-compat";
    };
    yallback = {
      url = "github:abathur/yallback";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.flake-utils.follows = "flake-utils";
      inputs.flake-compat.follows = "flake-compat";
    };
  };

  description = "generate and aggregate info about executables in nix packages";

  outputs = { self, nixpkgs, flake-utils, flake-compat, yallback }:
    {
      overlays.default = final: prev: {
        binlore = final.callPackage ./binlore.nix { binloreSrc = final.lib.cleanSource ./.; };
      };
    } // flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [
            yallback.overlays.default
            self.overlays.default
          ];
        };
        rules = ./execers.yar;
      in
        {
          # TODO: this errors because binlore has a pinocchio problem
          # (it isn't actually a derivation). Not sure if we should do
          # anything different here?
          # packages = {
          #   inherit (pkgs) binlore;
          #   default = pkgs.binlore;
          # };
          checks = {
            smoke = pkgs.binlore.collect { drvs = [pkgs.coreutils]; };
          };
          devShells = {
            default = pkgs.mkShell {
              buildInputs = [ pkgs.yara ];
              shellHook = ''
                binlore_yara(){
                  ${pkgs.yara}/bin/yara --scan-list ${rules} <(printf '%s\n' $1/{bin,lib,libexec})
                }
                echo "To see YARA rule matches for a package, run:"
                echo "binlore_yara {package (abspath)}/bin"
              '';
            };
          };
          # CI jobs; better way to declare?
          packages = let
            many = (import ./big.nix { inherit pkgs; });
            few = (import ./lil.nix { inherit pkgs; });
            matches = targets: pkgs.runCommand "yara-matches" { } ''
              binlore_yara()(
                set -x
                ${pkgs.yara}/bin/yara --scan-list --recursive --print-strings ${rules} <(printf '%s\n' $1/{bin,lib,libexec})
              )
              {
                echo ""
                for package in ${toString targets}; do
                  echo "YARA rule matches for package $package"
                  echo ""
                  binlore_yara $package
                  echo ""
                  echo "File types"
                  echo ""
                  ${pkgs.file}/bin/file -L $package/*/*
                  echo ""
                done
              } > $out
              '';
          in {
            big = (pkgs.binlore.collect { drvs = many; });
            smol = (pkgs.binlore.collect { drvs = few; });
            bigmatch = matches many;
            smolmatch = matches few;
          };
        }
    );
}
