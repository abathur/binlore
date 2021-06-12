{ pkgs ? import <nixpkgs> { } }:
with pkgs;
let
  rules = ./execers.yar;
  sudo = if pkgs.stdenv.isDarwin
    then pkgs.runCommand "impure-native-darwin-sudo" { } ''
      mkdir -p $out/bin
      ln -s /usr/bin/sudo $out/bin/sudo
      ln -s /usr/sbin/sudo $out/bin/visudo
    '' else pkgs.sudo;
  targets = [ sudo coreutils ];
in pkgs.mkShell {
  buildInputs = [ yara xxd sudo ];
  shellHook = ''
  binlore_yara(){
    ${yara}/bin/yara ${rules} $1
  }
  echo "To see YARA rule matches for a package, run:"
  echo "binlore_yara {package}/bin"
  '';
}
