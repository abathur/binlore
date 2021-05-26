{ pkgs ? import <nixpkgs> { } }:
with pkgs;
let
  inherit (pkgs.callPackage ./deps.nix { }) ouryara;
  rules = ./execers.yar;
  sudo = if pkgs.stdenv.isDarwin
    then pkgs.runCommand "impure-native-darwin-sudo" { } ''
      mkdir -p $out/bin
      ln -s /usr/bin/sudo $out/bin/sudo
      ln -s /usr/sbin/sudo $out/bin/visudo
    '' else pkgs.sudo;
  targets = [ sudo coreutils ];
in pkgs.mkShell {
  buildInputs = [ ouryara xxd sudo ];
  shellHook = ''
  binlore_yara(){
    ${ouryara}/bin/yara ${rules} $1
  }
  echo "To see YARA rule matches for a package, run:"
  echo "binlore_yara {package}/bin"
  '';
}
