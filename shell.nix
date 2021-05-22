{ pkgs ? import <nixpkgs> { } }:
with pkgs;
let
  inherit (pkgs.callPackage ./deps.nix { }) ouryara;
  rules = ./execers.yar;
  targets = [ curl gnused ps ];
in pkgs.mkShell {
  buildInputs = [ ouryara xxd ];
  shellHook = ''
  binlore_yara(){
    ${ouryara}/bin/yara ${rules} $1
  }
  echo "To see YARA rule matches for a package, run:"
  echo "binlore_yara {package}/bin"
  '';
}
